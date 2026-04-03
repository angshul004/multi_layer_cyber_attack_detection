from __future__ import annotations

import os


class Config:
    DB_USER = os.getenv("DB_USER") or os.getenv("MYSQLUSER") or "root"
    DB_PASSWORD = os.getenv("DB_PASSWORD") or os.getenv("MYSQLPASSWORD") or ""
    DB_HOST = os.getenv("DB_HOST") or os.getenv("MYSQLHOST") or "localhost"
    DB_PORT = os.getenv("DB_PORT") or os.getenv("MYSQLPORT") or "3306"
    DB_NAME = os.getenv("DB_NAME") or os.getenv("MYSQLDATABASE") or "cyber_security_db"
    RAILWAY_MYSQL_URL = os.getenv("MYSQL_URL")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "SQLALCHEMY_DATABASE_URI",
        RAILWAY_MYSQL_URL or f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
