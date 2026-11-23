from flask import Blueprint, render_template
from app import db
from app.models import Job

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    jobs = Job.query.order_by(Job.created_at.desc()).limit(20).all()
    return render_template("index.html", jobs=jobs)


@dashboard_bp.route("/report/<job_id>")
def report(job_id):
    job = db.session.get(Job, job_id)
    if not job:
        return render_template("index.html", jobs=[], error="Job not found"), 404
    return render_template("report.html", job=job)
