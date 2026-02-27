from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash
from models.user import User
from extensions import db

from services.login_anomaly_service import is_bruteforce_attempt
from services.risk_scoring_service import update_risk_score


from werkzeug.security import check_password_hash
from models.event_log import EventLog
import json
from datetime import datetime, timezone

from services.alert_service import evaluate_and_create_alert



auth_bp = Blueprint("auth_bp", __name__)

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    # Basic validation
    if not data or "username" not in data or "email" not in data or "password" not in data:
        return jsonify({"error": "Missing required fields"}), 400

    # Check if user already exists
    existing_user = User.query.filter(
        (User.username == data["username"]) | (User.email == data["email"])
    ).first()

    if existing_user:
        return jsonify({"error": "User already exists"}), 409

    # Hash password
    hashed_password = generate_password_hash(data["password"])

    # Create user
    user = User(
        username=data["username"],
        email=data["email"],
        password_hash=hashed_password
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201



@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing credentials"}), 400

    user = User.query.filter_by(username=data["username"]).first()

    # Case 1: User not found
    if not user:
        event = EventLog(
            user_id=0,  # unknown user cuz no user with id 0
            event_type="FAILED_LOGIN",
            event_data=json.dumps({
                "username": data["username"],
                "reason": "user_not_found",
                "time": str(datetime.now(timezone.utc))
            })
        )
        db.session.add(event)
        db.session.commit()

        return jsonify({"error": "Invalid username or password"}), 401

    # Case 2: Password incorrect
    if not check_password_hash(user.password_hash, data["password"]):

        event = EventLog(   # log failed_login attempt for existing user
            user_id=user.id,
            event_type="FAILED_LOGIN",
            event_data=json.dumps({
                "reason": "wrong_password",
                "time": str(datetime.now(timezone.utc))
            })
        )
        update_risk_score(user.id, 10)          # Increment risk score for failed login
        evaluate_and_create_alert(user.id)

        db.session.add(event)
        db.session.commit()

        # 🔴 Check for brute-force attack
        if is_bruteforce_attempt(user.id): 
            alert_event = EventLog(     # log security_alert for possible brute-force attack
                user_id=user.id,
                event_type="SECURITY_ALERT",
                event_data=json.dumps({
                    "alert": "Possible brute-force attack detected",
                    "time": str(datetime.now(timezone.utc))
                })
            )
            update_risk_score(user.id, 30)      #increment risk score if failed login>=3 in last 5 min
            evaluate_and_create_alert(user.id)

            db.session.add(alert_event)
            db.session.commit()

        return jsonify({"error": "Invalid username or password"}), 401


    # Case 3: Successful login
    event = EventLog(   # log successful login attempt
        user_id=user.id,
        event_type="SUCCESSFUL_LOGIN",
        event_data=json.dumps({
            "time": str(datetime.now(timezone.utc))
        })
    )
    db.session.add(event)
    db.session.commit()

    session["user_id"] = user.id
    session["is_admin"] = user.is_admin

    if user.is_admin:
        return jsonify({"redirect": "/admin/dashboard"})
    else:
        return jsonify({"redirect": "/dashboard"})
