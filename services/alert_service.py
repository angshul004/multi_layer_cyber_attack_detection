from datetime import datetime, timezone

from extensions import db
from models.alert import Alert
from models.risk_score import RiskScore
from services.correlation_service import detect_correlated_attack


def _append_message(existing_message, new_message):
    messages = [part.strip() for part in (existing_message or "").split(",") if part.strip()]
    if new_message not in messages:
        messages.append(new_message)
    return ", ".join(messages)


def evaluate_and_create_alert(user_id, trigger_message):
    risk = RiskScore.query.filter_by(user_id=user_id).first()
    if not risk:
        return

    if risk.score <= 20:
        severity = "LOW"
    elif risk.score <= 50:
        severity = "MEDIUM"
    else:
        severity = "HIGH"

    alert = Alert.query.filter_by(user_id=user_id).first()

    if alert is None:
        alert = Alert(
            user_id=user_id,
            severity=severity,
            message=trigger_message,
            created_at=datetime.now(timezone.utc),
        )
    else:
        alert.severity = severity
        alert.message = _append_message(alert.message, trigger_message)
        alert.created_at = datetime.now(timezone.utc)

    db.session.add(alert)
    db.session.commit()
    detect_correlated_attack(user_id)
