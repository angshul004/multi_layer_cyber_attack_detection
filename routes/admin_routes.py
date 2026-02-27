from flask import Blueprint, jsonify
from models.alert import Alert
from models.risk_score import RiskScore
from models.event_log import EventLog
from models.user import User
from extensions import db

import json

from services.auth_guard import admin_required
from flask import abort


admin_bp = Blueprint("admin_bp", __name__)

@admin_bp.route("/alerts", methods=["GET"])
def get_alerts():
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403

    alerts = Alert.query.order_by(Alert.created_at.desc()).all()
    result = []

    for alert in alerts:
        risk = RiskScore.query.filter_by(user_id=alert.user_id).first()

        result.append({
            "id": alert.id,
            "user_id": alert.user_id,
            "severity": alert.severity,
            "message": alert.message,
            "risk_score": risk.score if risk else 0,
            "created_at": alert.created_at.isoformat()
        })


    return jsonify(result), 200


@admin_bp.route("/users", methods=["GET"])
def get_users():
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403
    users = User.query.all()

    return jsonify([
        {
            "id": user.id,
            "username": user.username,
            "email": user.email
        }
        for user in users
    ])

@admin_bp.route("/user/<int:user_id>", methods=["GET"])
def get_user_profile(user_id):
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    risk = RiskScore.query.filter_by(user_id=user_id).first()
    
    # recent alerts
    alerts = Alert.query.filter_by(user_id=user_id)\
        .order_by(Alert.created_at.desc()).limit(5).all()
    
    # 10 activity logs 
    events = EventLog.query.filter_by(user_id=user_id)\
        .order_by(EventLog.created_at.desc()).limit(10).all()

    recent_events = []
    for e in events:
        parsed = json.loads(e.event_data) if e.event_data else {}
        recent_events.append({
            "event_type": e.event_type,
            "resource": parsed.get("resource", "N/A"),
            "reason": parsed.get("reason", ""),
            "url": parsed.get("url", ""),
            "created_at": e.created_at.isoformat()
        })

    return jsonify({
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email
        },
        "risk_score": risk.score if risk else 0,
        "recent_alerts": [
            {
                "severity": a.severity,
                "message": a.message,
                "created_at": a.created_at.isoformat()
            } for a in alerts
        ],
        "recent_events": recent_events

    })

@admin_bp.route("/user/<int:user_id>/timeline", methods=["GET"])
def user_timeline(user_id):
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403
    events = EventLog.query.filter_by(user_id=user_id)\
        .order_by(EventLog.created_at.asc()).all()

    timeline = []
    for e in events:
        parsed = json.loads(e.event_data) if e.event_data else {}
        timeline.append({
            "event_type": e.event_type,
            "reason": parsed.get("reason", ""),
            "resource": parsed.get("resource", ""),
            "created_at": e.created_at.isoformat()
        })

    return jsonify(timeline)


@admin_bp.route("/user/<int:user_id>/reset-security", methods=["POST"])
def reset_user_security(user_id):
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        EventLog.query.filter_by(user_id=user_id).delete()
        Alert.query.filter_by(user_id=user_id).delete()

        risk = RiskScore.query.filter_by(user_id=user_id).first()
        if risk:
            risk.score = 0
            db.session.add(risk)

        db.session.commit()
        return jsonify({"message": "User alerts/logs cleared and risk score reset"}), 200
    except Exception as exc:
        db.session.rollback()
        return jsonify({"error": "Failed to reset user security data", "details": str(exc)}), 500
