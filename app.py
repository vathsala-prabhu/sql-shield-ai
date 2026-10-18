import json
from pathlib import Path

from flask import Flask, request, jsonify, render_template, redirect
from werkzeug.exceptions import HTTPException

from database.db import init_db, list_incidents, get_incident
from security.gateway import process_request

app = Flask(__name__)
init_db()

METRICS_FILE = Path(__file__).resolve().parent / "models" / "metrics.json"

@app.get("/")
def home():
    return redirect("/detect")


@app.get("/detect")
def detect_page():
    return render_template("detect.html", active="detect")

@app.get("/incidents")
def incidents_page():
    return render_template("incidents.html", incidents=list_incidents(), active="incidents")

@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/detect")
def detect():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send JSON with a 'query' string."}), 400
    response, status = process_request(data.get("query"))
    return jsonify(response), status


@app.get("/api/incidents")
def incidents():
    return jsonify(list_incidents())


@app.get("/api/incidents/<int:incident_id>")
def incident_detail(incident_id):
    incident = get_incident(incident_id)
    if incident is None:
        return jsonify({"error": "Incident not found."}), 404
    return jsonify(incident)


@app.get("/api/metrics")
def metrics():
    if not METRICS_FILE.exists():
        return jsonify({"error": "Metrics not found. Run ml/evaluate.py."}), 404
    return jsonify(json.loads(METRICS_FILE.read_text()))


@app.errorhandler(Exception)
def handle_error(e):
    # Never expose stack traces to the user
    if isinstance(e, HTTPException):
        return jsonify({"error": e.name}), e.code
    app.logger.exception("Unexpected error")
    return jsonify({"error": "Internal server error."}), 500


if __name__ == "__main__":
    app.run(debug=False)