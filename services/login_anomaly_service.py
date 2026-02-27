from datetime import datetime, timedelta, timezone
from models.event_log import EventLog

def is_bruteforce_attempt(user_id):
    """
    Returns True if user has 3 or more failed logins
    in the last 5 minutes.
    """

    five_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=5)


    failed_attempts = EventLog.query.filter(
        EventLog.user_id == user_id,
        EventLog.event_type == "FAILED_LOGIN", # only count failed login attempts
        EventLog.created_at >= five_minutes_ago
    ).count()

    return failed_attempts >= 3
