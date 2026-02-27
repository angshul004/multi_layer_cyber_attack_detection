from flask import Blueprint, request, jsonify
from models.event_log import EventLog
from extensions import db
import json

#behavior detection
from services.behavior_anomaly_service import is_behavior_anomalous
from services.risk_scoring_service import update_risk_score
from services.alert_service import evaluate_and_create_alert


# Create Blueprint
event_bp = Blueprint("event_bp", __name__)

@event_bp.route("/log-action", methods=["POST"])
def log_user_action():
    """
    Logs general user activity for behavior analysis.
    Expected JSON:
    {
        "user_id": 1,
        "action_type": "PAGE_ACCESS",
        "resource": "/reports"
    }
    """

    data = request.get_json()

    if not data or "user_id" not in data or "action_type" not in data:
        return jsonify({"error": "Invalid action data"}), 400

    event = EventLog(   
        user_id=data["user_id"],
        event_type=data["action_type"], #logs page access, api call.
        event_data=json.dumps(data)
    )

    db.session.add(event)
    db.session.commit()

    # 🔴 Check for abnormal behavior
    if is_behavior_anomalous(data["user_id"]):
        update_risk_score(data["user_id"], 20)      # Increment risk score if 10+ actions in last 1 min
        evaluate_and_create_alert(data["user_id"])


    return jsonify({"message": "User action logged"}), 201
