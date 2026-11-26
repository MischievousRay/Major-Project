import json
import os
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.engine import static_analysis, emulation, rule_synthesis, validation

logger = logging.getLogger(__name__)


def run_pipeline(job_id, file_path, app):
    with app.app_context():
        from app import db
        from app.models import Job, StaticResult, DynamicResult, YaraRule

        job = db.session.get(Job, job_id)
        if not job:
            logger.error(f"Job {job_id} not found")
            return

        job.status = "EXECUTING"
        db.session.commit()

        static_result = None
        dynamic_result = None

        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                static_future = executor.submit(
                    static_analysis.analyze,
                    file_path,
                    app.config.get("ENTROPY_PACKING_THRESHOLD", 7.2),
                )
                dynamic_future = executor.submit(
                    emulation.emulate,
                    file_path,
                    app.config.get("EMULATION_TIMEOUT_SECONDS", 20),
                    app.config.get("EMULATION_MAX_INSTRUCTIONS", 1_000_000),
                )

                for future in as_completed([static_future, dynamic_future]):
                    if future == static_future:
                        static_result = future.result()
                    else:
                        dynamic_result = future.result()

        except Exception as e:
            logger.error(f"Pipeline error for job {job_id}: {e}")
            job.status = "FAILED"
            db.session.commit()
            return

        if static_result is None:
            static_result = {
                "imphash": None, "sections": [], "suspicious_strings": [],
                "compilation_timestamp": None, "architecture": None, "section_count": 0,
                "error": "Static analysis returned no result",
            }
        if dynamic_result is None:
            dynamic_result = {
                "behaviors": [], "emulation_success": False,
                "error_message": "Dynamic analysis returned no result",
            }

        sr = StaticResult(
            job_id=job_id,
            imphash=static_result.get("imphash"),
            compilation_timestamp=static_result.get("compilation_timestamp"),
            architecture=static_result.get("architecture"),
            section_count=static_result.get("section_count", 0),
            sections_json=json.dumps(static_result.get("sections", [])),
            suspicious_strings_json=json.dumps(static_result.get("suspicious_strings", [])),
        )
        db.session.add(sr)

        dr = DynamicResult(
            job_id=job_id,
            behaviors_json=json.dumps(dynamic_result.get("behaviors", [])),
            emulation_success=dynamic_result.get("emulation_success", False),
            error_message=dynamic_result.get("error_message"),
        )
        db.session.add(dr)

        rule_name, rule_text, filtered_strings = rule_synthesis.synthesize(
            sha256=job.sha256,
            static_result=static_result,
            dynamic_result=dynamic_result,
            match_threshold=app.config.get("YARA_STRING_MATCH_THRESHOLD", 3),
        )

        clean_dir = app.config.get("CLEAN_SAMPLES_DIR", "clean_samples")
        final_rule, val_status, fp_count = validation.validate(rule_text, clean_dir)

        rules_dir = app.config.get("RULES_OUTPUT_DIR", "rules")
        os.makedirs(rules_dir, exist_ok=True)
        rule_file_path = os.path.join(rules_dir, f"{rule_name}.yar")
        with open(rule_file_path, "w", encoding="utf-8") as f:
            f.write(final_rule)

        yr = YaraRule(
            job_id=job_id,
            rule_name=rule_name,
            rule_text=final_rule,
            validation_status=val_status,
            false_positive_count=fp_count,
        )
        db.session.add(yr)

        job.status = "COMPLETED"
        job.completed_at = datetime.now(timezone.utc)
        db.session.commit()

        logger.info(f"Pipeline completed for job {job_id}: rule={rule_name}, validation={val_status}")
