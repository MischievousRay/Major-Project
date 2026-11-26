import threading
from flask import Blueprint, request, jsonify, current_app
from app import db
from app.models import Job
from app.engine.ingestion import compute_sha256, validate_mz_header, generate_job_id, save_sample
from app.engine.pipeline import run_pipeline

api_bp = Blueprint("api", __name__)


@api_bp.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided in the request"}), 400

    file = request.files["file"]
    if file.filename == "" or file.filename is None:
        return jsonify({"error": "No file selected"}), 400

    try:
        file_data = file.read()
    except Exception as e:
        return jsonify({"error": f"Failed to read uploaded file: {str(e)}"}), 400

    if not file_data:
        return jsonify({"error": "Uploaded file is empty"}), 400

    sha256 = compute_sha256(file_data)

    existing_job = Job.query.filter_by(sha256=sha256).first()
    if existing_job:
        return jsonify({
            "message": "File has already been analyzed",
            "job_id": existing_job.id,
            "filename": existing_job.filename,
            "sha256": existing_job.sha256,
            "status": existing_job.status,
            "file_path": existing_job.file_path,
            "duplicate": True,
        }), 200

    if not validate_mz_header(file_data):
        return jsonify({
            "error": "Invalid file format. Only Windows PE executables (MZ header) are accepted."
        }), 422

    upload_folder = current_app.config["UPLOAD_FOLDER"]
    file_path = save_sample(file_data, sha256, upload_folder)

    job_id = generate_job_id()
    while db.session.get(Job, job_id):
        job_id = generate_job_id()

    job = Job(
        id=job_id,
        filename=file.filename,
        sha256=sha256,
        status="QUEUED",
        file_path=file_path,
    )
    db.session.add(job)
    db.session.commit()

    app = current_app._get_current_object()
    thread = threading.Thread(
        target=run_pipeline,
        args=(job_id, file_path, app),
        daemon=True,
    )
    thread.start()

    return jsonify({
        "job_id": job_id,
        "filename": file.filename,
        "sha256": sha256,
        "status": "QUEUED",
        "file_path": file_path,
        "duplicate": False,
    }), 202


@api_bp.route("/status/<job_id>", methods=["GET"])
def get_status(job_id):
    job = db.session.get(Job, job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "job_id": job.id,
        "filename": job.filename,
        "sha256": job.sha256,
        "status": job.status,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }), 200


@api_bp.route("/report/<job_id>", methods=["GET"])
def get_report(job_id):
    job = db.session.get(Job, job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job.to_dict()), 200


@api_bp.route("/rules/<job_id>", methods=["GET"])
def get_rule(job_id):
    job = db.session.get(Job, job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if not job.yara_rule:
        return jsonify({"error": "YARA rule not yet generated"}), 404
    from flask import Response
    return Response(
        job.yara_rule.rule_text,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={job.yara_rule.rule_name}.yar"},
    )


@api_bp.route("/jobs", methods=["GET"])
def list_jobs():
    jobs = Job.query.order_by(Job.created_at.desc()).limit(50).all()
    return jsonify([
        {
            "job_id": j.id,
            "filename": j.filename,
            "sha256": j.sha256,
            "status": j.status,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "completed_at": j.completed_at.isoformat() if j.completed_at else None,
        }
        for j in jobs
    ]), 200


@api_bp.route("/jobs/stats", methods=["GET"])
def jobs_stats():
    """Return aggregate statistics for the dashboard."""
    from app.models import DynamicResult, YaraRule
    total = Job.query.count()
    completed = Job.query.filter_by(status="COMPLETED").count()
    failed = Job.query.filter_by(status="FAILED").count()
    in_progress = Job.query.filter(Job.status.in_(["QUEUED", "EXECUTING"])).count()
    emulation_success = db.session.query(DynamicResult).filter_by(emulation_success=True).count()
    total_fp = db.session.query(
        db.func.sum(YaraRule.false_positive_count)
    ).scalar() or 0
    rules_passed = db.session.query(YaraRule).filter_by(validation_status="PASSED").count()
    return jsonify({
        "total_jobs": total,
        "completed": completed,
        "failed": failed,
        "in_progress": in_progress,
        "emulation_success_count": emulation_success,
        "total_false_positives_remediated": int(total_fp),
        "rules_passed_validation": rules_passed,
    }), 200
