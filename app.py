"""Chhaya: independent Flask entry point."""
from flask import Flask

def create_app():
    app = Flask(__name__)
    @app.get("/api/health")
    def health():
        return {"status": "ok", "app": "Chhaya"}
    return app

if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=8114, debug=False)
