import json
from datetime import datetime, timezone
from app import db


class Job(db.Model):
    __tablename__ = "jobs"

    id = db.Column(db.String(12), primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default="QUEUED")
    file_path = db.Column(db.String(512), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)

    static_result = db.relationship("StaticResult", backref="job", uselist=False, cascade="all, delete-orphan")
    dynamic_result = db.relationship("DynamicResult", backref="job", uselist=False, cascade="all, delete-orphan")
    yara_rule = db.relationship("YaraRule", backref="job", uselist=False, cascade="all, delete-orphan")

    def to_dict(self):
        result = {
            "job_id": self.id,
            "filename": self.filename,
            "sha256": self.sha256,
            "status": self.status,
            "file_path": self.file_path,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
        if self.static_result:
            result["static_analysis"] = self.static_result.to_dict()
        if self.dynamic_result:
            result["dynamic_analysis"] = self.dynamic_result.to_dict()
        if self.yara_rule:
            result["yara_rule"] = self.yara_rule.to_dict()
        return result


class StaticResult(db.Model):
    __tablename__ = "static_results"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    job_id = db.Column(db.String(12), db.ForeignKey("jobs.id"), nullable=False)
    imphash = db.Column(db.String(32), nullable=True)
    compilation_timestamp = db.Column(db.String(64), nullable=True)
    architecture = db.Column(db.String(32), nullable=True)
    section_count = db.Column(db.Integer, nullable=True)
    sections_json = db.Column(db.Text, nullable=True)
    suspicious_strings_json = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "imphash": self.imphash,
            "compilation_timestamp": self.compilation_timestamp,
            "architecture": self.architecture,
            "section_count": self.section_count,
            "sections": json.loads(self.sections_json) if self.sections_json else [],
            "suspicious_strings": json.loads(self.suspicious_strings_json) if self.suspicious_strings_json else [],
        }


class DynamicResult(db.Model):
    __tablename__ = "dynamic_results"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    job_id = db.Column(db.String(12), db.ForeignKey("jobs.id"), nullable=False)
    behaviors_json = db.Column(db.Text, nullable=True)
    emulation_success = db.Column(db.Boolean, default=False)
    error_message = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "behaviors": json.loads(self.behaviors_json) if self.behaviors_json else [],
            "emulation_success": self.emulation_success,
            "error_message": self.error_message,
        }


class YaraRule(db.Model):
    __tablename__ = "yara_rules"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    job_id = db.Column(db.String(12), db.ForeignKey("jobs.id"), nullable=False)
    rule_name = db.Column(db.String(128), nullable=False)
    rule_text = db.Column(db.Text, nullable=False)
    validation_status = db.Column(db.String(20), nullable=False, default="PENDING")
    false_positive_count = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            "rule_name": self.rule_name,
            "rule_text": self.rule_text,
            "validation_status": self.validation_status,
            "false_positive_count": self.false_positive_count,
        }
