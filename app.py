import json
from pathlib import Path

from flask import Flask, request, jsonify, render_template, redirect, url_for
from werkzeug.exceptions import HTTPException

from config import config
from database.db import (
    init_db,
    list_incidents,
    get_incident,
    get_stats,
    clear_incidents,
    delete_incident,
)
from security.gateway import process_request
from services.security_analyst import analyze_incident

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY

# Ensure database tables exist at startup
init_db()

METRICS_FILE = config.MODELS_DIR / "metrics.json"


def load_metrics():
    """Helper to safely read real evaluation metrics from models/metrics.json."""
    if METRICS_FILE.exists():
        try:
            return json.loads(METRICS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


# -----------------------------------------------------------------------------
# Frontend Page Routes
# -----------------------------------------------------------------------------

@app.get("/")
def dashboard_page():
    stats = get_stats()
    metrics = load_metrics()
    recent = list_incidents(limit=10)
    return render_template(
        "index.html",
        active="dashboard",
        stats=stats,
        metrics=metrics,
        recent_incidents=recent,
        config=config,
    )


@app.get("/detect")
def detect_page():
    return render_template(
        "detect.html",
        active="detect",
        config=config,
    )


@app.get("/simulation")
def simulation_page():
    return render_template(
        "simulation.html",
        active="simulation",
        config=config,
    )


@app.get("/incidents")
def incidents_page():
    action = request.args.get("action")
    severity = request.args.get("severity")
    search = request.args.get("search")
    incidents_list = list_incidents(limit=150, action=action, severity=severity, search=search)
    stats = get_stats()
    return render_template(
        "incidents.html",
        active="incidents",
        incidents=incidents_list,
        stats=stats,
        current_action=action or "",
        current_severity=severity or "",
        current_search=search or "",
        config=config,
    )


@app.get("/incidents/<int:incident_id>")
def incident_detail_page(incident_id):
    incident = get_incident(incident_id)
    if incident is None:
        return render_template("404.html", message=f"Incident #{incident_id} was not found."), 404
    return render_template(
        "incident_detail.html",
        active="incidents",
        incident=incident,
        config=config,
    )


@app.get("/model-comparison")
def model_comparison_page():
    metrics = load_metrics()
    return render_template(
        "model_comparison.html",
        active="models",
        metrics=metrics,
        config=config,
    )


@app.get("/analyst")
def analyst_page():
    incident_id = request.args.get("incident_id")
    incident = None
    if incident_id and incident_id.isdigit():
        incident = get_incident(int(incident_id))
    return render_template(
        "analyst.html",
        active="analyst",
        initial_incident=incident,
        config=config,
    )


# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "SQL SHIELD AI",
        "active_model": config.ACTIVE_MODEL,
        "default_threshold": config.DEFAULT_THRESHOLD,
    })


@app.get("/api/stats")
def stats_api():
    return jsonify(get_stats())


@app.post("/api/detect")
def detect_api():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object containing a 'query' string."}), 400

    query = data.get("query")
    threshold = data.get("threshold")
    model_name = data.get("model")

    if threshold is not None:
        try:
            threshold = float(threshold)
            if not (0.0 <= threshold <= 1.0):
                return jsonify({"error": "Threshold must be a decimal between 0.0 and 1.0."}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Threshold must be a numeric value."}), 400

    response, status = process_request(query, threshold=threshold, model_name=model_name)
    return jsonify(response), status


@app.get("/api/incidents")
def incidents_api():
    limit = request.args.get("limit", 100)
    try:
        limit = min(max(int(limit), 1), 500)
    except ValueError:
        limit = 100
    action = request.args.get("action")
    severity = request.args.get("severity")
    search = request.args.get("search")
    return jsonify(list_incidents(limit=limit, action=action, severity=severity, search=search))


@app.get("/api/incidents/<int:incident_id>")
def incident_detail_api(incident_id):
    incident = get_incident(incident_id)
    if incident is None:
        return jsonify({"error": f"Incident #{incident_id} not found."}), 404
    return jsonify(incident)


@app.post("/api/incidents/clear")
def clear_incidents_api():
    clear_incidents()
    return jsonify({
        "status": "success",
        "message": "All demonstration incident records have been safely cleared.",
    })


@app.delete("/api/incidents/<int:incident_id>")
def delete_incident_api(incident_id):
    incident = get_incident(incident_id)
    if incident is None:
        return jsonify({"error": f"Incident #{incident_id} not found."}), 404
    delete_incident(incident_id)
    return jsonify({"status": "success", "deleted_id": incident_id})


@app.get("/api/metrics")
def metrics_api():
    metrics = load_metrics()
    if not metrics:
        return jsonify({"error": "Metrics not found. Run ml/evaluate.py to compute."}), 404
    return jsonify(metrics)


@app.post("/api/security-analyst")
def security_analyst_api():
    data = request.get_json(silent=True) or {}
    incident_id = data.get("incident_id")
    user_question = data.get("question")

    incident_data = {}
    if incident_id:
        try:
            found = get_incident(int(incident_id))
            if found:
                incident_data = found
        except (ValueError, TypeError):
            pass

    # If no incident_id or incident not found, check if raw query was supplied
    if not incident_data and data.get("query"):
        # Run a quick gateway preview without re-saving as new incident if requested
        preview, _ = process_request(data.get("query"))
        incident_data = preview

    if not incident_data:
        return jsonify({"error": "Provide an 'incident_id' or a 'query' to analyze."}), 400

    analysis_res = analyze_incident(incident_data, user_question=user_question)
    return jsonify(analysis_res)


# -----------------------------------------------------------------------------
# Error Handlers
# -----------------------------------------------------------------------------

@app.errorhandler(404)
def not_found_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Endpoint not found."}), 404
    return render_template("404.html", message="The requested page could not be found."), 404


@app.errorhandler(Exception)
def handle_error(e):
    # Never expose internal stack traces to the client
    if isinstance(e, HTTPException):
        if request.path.startswith("/api/"):
            return jsonify({"error": e.description}), e.code
        return render_template("404.html", message=e.description), e.code
    app.logger.exception("Unexpected server error")
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error occurred."}), 500
    return render_template("404.html", message="An unexpected server error occurred."), 500


if __name__ == "__main__":
    print(f"SQL SHIELD AI starting on http://127.0.0.1:5000 (Debug: {config.DEBUG})")
    app.run(host="127.0.0.1", port=5000, debug=config.DEBUG)