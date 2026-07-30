import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    # threaded so the capture loop and request handling coexist
    app.run(host=host, port=port, debug=debug, threaded=True,
            use_reloader=False)
