import os
import traceback
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.exceptions import RequestEntityTooLarge
from config import Config

db = SQLAlchemy()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["CLEAN_SAMPLES_DIR"], exist_ok=True)
    os.makedirs(app.config["RULES_OUTPUT_DIR"], exist_ok=True)

    @app.errorhandler(413)
    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "File too large. Maximum size is 16 MB."}), 413
        return e

    @app.errorhandler(500)
    def handle_internal_error(e):
        app.logger.error(f"Internal server error: {traceback.format_exc()}")
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal server error occurred during processing."}), 500
        return e

    @app.errorhandler(400)
    def handle_bad_request(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": str(e.description) if hasattr(e, 'description') else "Bad request."}), 400
        return e

    from app.routes.api import api_bp
    from app.routes.dashboard import dashboard_bp

    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(dashboard_bp)

    with app.app_context():
        from app import models  # noqa: F401
        db.create_all()

    return app
