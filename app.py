from __future__ import annotations

import os

from dotenv import load_dotenv
from flask import Flask, redirect, render_template, session

from config import Config
from extensions import db
from routes.admin_routes import admin_bp
from routes.auth_routes import auth_bp
from routes.event_routes import event_bp
from routes.phishing_routes import phishing_bp

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)

secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY is not set. Add it to your .env file.")
app.secret_key = secret_key

db.init_app(app)

app.register_blueprint(event_bp, url_prefix="/api")
app.register_blueprint(auth_bp, url_prefix="/api")
app.register_blueprint(admin_bp, url_prefix="/api/admin")
app.register_blueprint(phishing_bp, url_prefix="/api")


@app.route("/")
def home():
    if "user_id" in session:
        if session.get("is_admin"):
            return redirect("/admin/dashboard")
        return redirect("/dashboard")
    return render_template("home.html")


@app.route("/register")
def register_page():
    return render_template("home.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    if "user_id" not in session or not session.get("is_admin"):
        return redirect("/login")
    return render_template("admin_dashboard.html")


@app.route("/dashboard")
def user_dashboard():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("user_dashboard.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/activity")
def activity_page():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("activity.html", user_id=session["user_id"])


@app.route("/url-scan")
def url_scan_page():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("url_scan.html")


@app.route("/admin/user-profile/<int:user_id>")
def user_profile(user_id):
    if "user_id" not in session or not session.get("is_admin"):
        return redirect("/login")
    return render_template("user_profile.html", user_id=user_id)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)
