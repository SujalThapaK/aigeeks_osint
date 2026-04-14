"""
OSINT Intelligence Platform — Flask REST API
=============================================

Endpoints:
  POST /api/investigate          Start a new investigation job
  GET  /api/status/<job_id>      Poll job status + results
  GET  /api/download/<job_id>    Stream the generated PDF
  GET  /health                   Health check

The server runs each investigation in a daemon thread so the HTTP
response returns immediately with a job_id for async polling.
"""

import logging
import os
import json
import asyncio
import threading
from dataclasses import asdict
from datetime import datetime

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] [%(name)s] %(levelname)s: %(message)s",
    force=True,
)

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

from osint_engine import run_investigation
from report_generator import generate_pdf

app = Flask(__name__)
CORS(app)
app.logger.handlers = logging.getLogger().handlers
app.logger.setLevel(logging.DEBUG)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# In-memory job store  {job_id: {...}}
jobs: dict = {}


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

def _run_job(job_id: str, target: str) -> None:
    jobs[job_id]["status"] = "running"

    def progress_cb(adapter_name: str, current: int, total: int) -> None:
        jobs[job_id]["progress"].append({
            "adapter": adapter_name,
            "step":    current,
            "total":   total,
            "message": f"Running {adapter_name}...",
        })

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        report = loop.run_until_complete(
            run_investigation(target, progress_cb)
        )
        loop.close()

        report_dict = asdict(report)
        jobs[job_id]["report"] = report_dict
        jobs[job_id]["status"] = "complete"

        # Generate PDF
        safe = target.replace(" ", "_").replace("/", "_")[:40]
        pdf_name = f"osint_{safe}_{job_id[:8]}.pdf"
        pdf_path = os.path.join(REPORTS_DIR, pdf_name)
        generate_pdf(report_dict, pdf_path)
        jobs[job_id]["pdf_path"] = pdf_path
        jobs[job_id]["pdf_name"] = pdf_name

    except Exception as exc:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"]  = str(exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/api/investigate", methods=["POST"])
def start_investigation():
    body = request.get_json(silent=True) or {}
    target      = (body.get("target") or "").strip().title()

    if not target:
        return jsonify({"error": "target is required"}), 400

    job_id = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    jobs[job_id] = {
        "job_id":      job_id,
        "target":      target,
        "status":      "queued",
        "progress":    [],
    }

    t = threading.Thread(
        target=_run_job,
        args=(job_id, target),
        daemon=True,
    )
    t.start()

    return jsonify({"job_id": job_id}), 202


@app.route("/api/status/<job_id>", methods=["GET"])
def job_status(job_id: str):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404

    result = {
        "job_id":   job_id,
        "status":   job["status"],
        "progress": job.get("progress", []),
    }

    if job["status"] == "complete":
        rpt = job["report"]
        entity_map = rpt["entity_map"].copy() if isinstance(rpt["entity_map"], dict) else rpt["entity_map"]
        if entity_map and entity_map.get("primary_photo_local"):
            host = request.host_url.rstrip("/")
            entity_map["primary_photo_local_url"] = f"{host}/api/photo/{job_id}"

        result["pdf_name"] = job.get("pdf_name")
        result["summary"]  = {
            "target":             rpt["target"],
            "total_sources":      rpt["total_sources"],
            "adapters_used":      rpt["adapters_used"],
            "executive_summary":  rpt["executive_summary"],
            "entity_map":         entity_map,
            "findings_count":     len(rpt["findings"]),
        }
        result["findings"] = rpt["findings"]

    if job["status"] == "error":
        result["error"] = job.get("error")

    return jsonify(result)


@app.route("/api/photo/<job_id>", methods=["GET"])
def serve_report_photo(job_id: str):
    job = jobs.get(job_id)
    if not job or job.get("status") != "complete":
        return jsonify({"error": "image not available"}), 404
    rpt = job.get("report", {})
    entity_map = rpt.get("entity_map", {})
    photo_path = entity_map.get("primary_photo_local")
    if not photo_path or not os.path.exists(photo_path):
        return jsonify({"error": "image file not found"}), 404
    return send_file(photo_path, mimetype="image/jpeg")


@app.route("/api/download/<job_id>", methods=["GET"])
def download_report(job_id: str):
    job = jobs.get(job_id)
    if not job or job.get("status") != "complete":
        return jsonify({"error": "report not ready"}), 404
    pdf_path = job.get("pdf_path", "")
    if not pdf_path or not os.path.exists(pdf_path):
        return jsonify({"error": "PDF file not found on disk"}), 404
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=job["pdf_name"],
        mimetype="application/pdf",
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "jobs": len(jobs)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"OSINT Engine API starting on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
