from app import app
if __name__ == "__main__":
    # Changes for mbm docker container
    app.run(host="0.0.0.0", port=5000, debug=True)