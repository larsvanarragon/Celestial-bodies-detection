"""Forward Flask traffic snapshots to a collector without replacing the app.

Each message is one length-prefixed pickle of a plain dict. The frame is a
4-byte big-endian length followed by that many pickle bytes. Request and
response messages that belong to the same exchange share ``id``.

The body is raw bytes. ``Request`` itself is not serialized: it is bound to
the WSGI environment of this process and cannot be replayed elsewhere.
"""

import logging
import os
import pickle
import socket
import struct
import threading
import uuid

from flask import g, request

logger = logging.getLogger(__name__)

_HEADER = struct.Struct("!I")
_MAX_FRAME = 128 * 1024 * 1024


def register_traffic_interceptor(app, host=None, port=None, timeout=0.5):
    """Record every request and response, then continue normal handling.

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
        self._lock = threading.Lock()
        self._sock = None
        self._warned = False

    def capture_request(self):
        # cache=True keeps the body readable for the route that runs next.
        body = request.get_data(cache=True)
        traffic_id = str(uuid.uuid4())
        g.traffic_id = traffic_id
        self._send(
            {
                "kind": "request",
                "id": traffic_id,
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
        self._send(
            {
                "kind": "response",
                "id": getattr(g, "traffic_id", None),
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": _response_body(response),
            }
        )
        return response

    def _send(self, message):
        payload = pickle.dumps(message, protocol=4)
        frame = _HEADER.pack(len(payload)) + payload
        with self._lock:
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
