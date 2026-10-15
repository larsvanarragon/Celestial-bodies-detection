"""Forward Flask traffic snapshots to a collector without replacing the app.

The request hooks enqueue a snapshot on a FIFO queue and return immediately.
One background thread takes snapshots in that order, serializes each one, and
writes it to the collector socket.

Each message is one length-prefixed pickle of a plain dict. The frame is a
4-byte big-endian length followed by that many pickle bytes. Messages from
the same browser share ``id`` and ``user_id``. ``user_id`` is an incrementing
integer. ``id`` is the session id: a value the client sends in the
``X-Session-Id`` header, or otherwise one allocated once and stored in the
Flask session. A homepage and the later image submission therefore carry the
same session id. A request and its response share that id as well.

The body is raw bytes. ``Request`` itself is not serialized: it is bound to
the WSGI environment of this process and cannot be replayed elsewhere.

Only ``GET /`` and ``POST /`` are recorded. A response is recorded only when
it belongs to one of those requests, and it keeps that request's session id.

When ``POST /`` answers with a redirect, the redirect itself is not recorded.
The same user's next ``GET`` to the redirect target is not recorded as a
request; its response is recorded as the response of the ``POST``.
"""

import logging
import os
import pickle
import queue
import re
import socket
import struct
import threading
import uuid
from urllib.parse import urlsplit

from flask import g, request, session

logger = logging.getLogger(__name__)

_HEADER = struct.Struct("!I")
_MAX_FRAME = 128 * 1024 * 1024
_CAPTURED = {("GET", "/"), ("POST", "/")}
# Sent by the simulator on every request of one user. A browser omits it.
_SESSION_HEADER = "X-Session-Id"
_SESSION_TOKEN = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")


def register_traffic_interceptor(app, host=None, port=None, timeout=0.5):
    """Record GET and POST on ``/`` and their responses, then continue handling.

    Set ``TRAFFIC_SOCKET_HOST`` to an empty string to leave the app unchanged.
    The default collector is ``127.0.0.1:9000``. A missing collector is logged
    and does not fail the request.
    """
    if host is None:
        host = os.environ.get("TRAFFIC_SOCKET_HOST", "127.0.0.1")
    if port is None:
        port = int(os.environ.get("TRAFFIC_SOCKET_PORT", "9000"))
    if not host:
        logger.info("Traffic interceptor disabled")
        return None

    interceptor = TrafficInterceptor(host, int(port), float(timeout))
    app.before_request(interceptor.capture_request)
    app.after_request(interceptor.capture_response)
    return interceptor


class TrafficInterceptor:
    def __init__(self, host, port, timeout):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._queue = queue.Queue()
        self._sock = None
        self._warned = False
        self._next_user_id = 1
        self._user_id_lock = threading.Lock()
        # user_id -> (traffic_id, redirect target path) of a POST awaiting its result
        self._pending = {}
        self._pending_lock = threading.Lock()
        self._sender = threading.Thread(
            target=self._sender_loop,
            name="traffic-interceptor",
            daemon=True,
        )
        self._sender.start()

    def capture_request(self):
        if self._resume_redirect():
            return
        if (request.method, request.path) not in _CAPTURED:
            return
        # cache=True keeps the body readable for the route that runs next.
        body = request.get_data(cache=True)
        user_id, session_id = self._browser_session()
        g.traffic_id = session_id
        g.traffic_user_id = user_id
        self._send(
            {
                "kind": "request",
                "id": session_id,
                "user_id": user_id,
                "method": request.method,
                "scheme": request.scheme,
                "host": request.host,
                "path": request.path,
                "query_string": request.query_string.decode("ascii", errors="replace"),
                "headers": dict(request.headers),
                "remote_addr": request.remote_addr,
                "body": body,
            }
        )

    def capture_response(self, response):
        if getattr(g, "traffic_id", None) is None:
            return response
        if request.method == "POST" and response.status_code in (301, 302, 303, 307, 308):
            with self._pending_lock:
                self._pending[g.traffic_user_id] = (
                    g.traffic_id,
                    urlsplit(response.location or "").path,
                )
            return response
        self._send(
            {
                "kind": "response",
                "id": getattr(g, "traffic_id", None),
                "user_id": getattr(g, "traffic_user_id", None),
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": _response_body(response),
            }
        )
        return response

    def _resume_redirect(self):
        """Adopt the exchange of a redirected POST if this request follows it."""
        user_id = session.get("user_id")
        if not isinstance(user_id, int):
            return False
        with self._pending_lock:
            pending = self._pending.pop(user_id, None)
        if pending is None:
            return False
        traffic_id, target = pending
        if request.method != "GET" or request.path != target:
            return False
        g.traffic_id = traffic_id
        g.traffic_user_id = user_id
        return True

    def _browser_session(self):
        """User id and the session id shared by this browser's requests."""
        user_id = session.get("user_id")
        if not isinstance(user_id, int):
            user_id = self._allocate_user_id()
            session["user_id"] = user_id

        supplied = request.headers.get(_SESSION_HEADER, "").strip()
        if _SESSION_TOKEN.fullmatch(supplied):
            if session.get("session_id") != supplied:
                session["session_id"] = supplied
            return user_id, supplied

        session_id = session.get("session_id")
        if not isinstance(session_id, str) or not _SESSION_TOKEN.fullmatch(session_id):
            session_id = str(uuid.uuid4())
            session["session_id"] = session_id
        return user_id, session_id

    def _allocate_user_id(self):
        with self._user_id_lock:
            user_id = self._next_user_id
            self._next_user_id += 1
            return user_id

    def _send(self, message):
        self._queue.put(message)

    def _sender_loop(self):
        while True:
            message = self._queue.get()
            try:
                self._deliver(message)
            except Exception:
                logger.exception("Traffic interceptor failed to send a snapshot")
            finally:
                self._queue.task_done()

    def _deliver(self, message):
        payload = pickle.dumps(message, protocol=4)
        frame = _HEADER.pack(len(payload)) + payload
        try:
            self._socket().sendall(frame)
        except OSError as exc:
            self._close()
            if not self._warned:
                logger.warning(
                    "Traffic interceptor cannot reach %s:%s (%s); "
                    "the app continues to handle requests locally",
                    self.host,
                    self.port,
                    exc,
                )
                self._warned = True
            else:
                logger.debug("Traffic forward failed: %s", exc)
        else:
            self._warned = False

    def _socket(self):
        if self._sock is None:
            conn = socket.create_connection((self.host, self.port), self.timeout)
            conn.settimeout(self.timeout)
            self._sock = conn
        return self._sock

    def _close(self):
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def read_traffic_message(sock):
    """Read one frame written by the interceptor."""
    header = _read_exact(sock, _HEADER.size)
    (length,) = _HEADER.unpack(header)
    if length > _MAX_FRAME:
        raise ValueError(f"traffic frame is {length} bytes, limit is {_MAX_FRAME}")
    return pickle.loads(_read_exact(sock, length))


def _read_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("collector closed the traffic socket")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _response_body(response):
    try:
        return response.get_data()
    except RuntimeError:
        # Static and file responses can be in direct-passthrough mode.
        return b""
