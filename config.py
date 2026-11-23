import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "amts-engine-dev-key-change-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'amts_engine.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    CLEAN_SAMPLES_DIR = os.path.join(BASE_DIR, "clean_samples")
    RULES_OUTPUT_DIR = os.path.join(BASE_DIR, "rules")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ENTROPY_PACKING_THRESHOLD = 7.2
    EMULATION_TIMEOUT_SECONDS = 20
    EMULATION_MAX_INSTRUCTIONS = 1_000_000
    MIN_STRING_LENGTH = 4
    YARA_STRING_MATCH_THRESHOLD = 3
