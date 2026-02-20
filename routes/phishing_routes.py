from __future__ import annotations

import json
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, session

from extensions import db
from models.event_log import EventLog
from services.phishing_detector import scan_url


phishing_bp = Blueprint("phishing_bp", __name__)


@phishing_bp.route("/scan-url", methods=["POST"])
def scan_url_endpoint():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    try:
        result = scan_url(url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 503
    except Exception as exc:
        return jsonify({"error": "URL scan failed", "details": str(exc)}), 500

    try:
        event_payload = {
            "url": url,
            "prediction": result["prediction"],
            "confidence": result["confidence"],
            "features": result["features"],
            "time": str(datetime.now(timezone.utc)),
        }

        event = EventLog(
            user_id=session["user_id"],
            event_type="URL_SCAN",
            event_data=json.dumps(event_payload),
        )
        db.session.add(event)
        db.session.commit()

        return jsonify(result), 200

    except Exception as exc:
        db.session.rollback()
        return jsonify({"error": "Failed to process scan result", "details": str(exc)}), 500
