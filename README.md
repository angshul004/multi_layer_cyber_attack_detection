# SentinelX - Multi-Layer Cyber Attack Detection System

SentinelX is a Flask-based cybersecurity monitoring application that combines authentication monitoring, behavior anomaly detection, risk scoring, alerting, and machine-learning URL phishing detection in one platform.

## Features
- Session-based user authentication with `is_admin` role support
- Event logging pipeline for security and activity events
- Login anomaly detection (failed-login and brute-force patterns)
- Behavior anomaly detection (abnormal user actions/API spikes)
- Dynamic risk scoring and alert generation
- Admin dashboard for users, alerts, timelines, and recent events
- URL phishing detection page and API using a trained ML model

## Project Structure
```text
multi_layer_cyber_attack_detection/
  app.py
  config.py
  extensions.py
  models/
  routes/
  services/
  templates/
  ml_models/
    phishing_site_urls.csv
    feature_extractor.py
    train_phishing_model_optimized.py
    phishing_model_optimized.pkl   (generated after training)
```

## Tech Stack
- Backend: Flask, Flask-SQLAlchemy
- Database: MySQL (via PyMySQL)
- ML: scikit-learn (RandomForest)
- Frontend: HTML, Bootstrap, JavaScript

## Prerequisites
- Python 3.10+
- MySQL running locally
- `pip` and virtual environment support

## Setup
1. Clone repository:
```bash
git clone <your-repo-url>
cd multi_layer_cyber_attack_detection
```

2. Create and activate virtual environment:
```bash
python -m venv venv
```
Windows PowerShell:
```powershell
.\venv\Scripts\Activate.ps1
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure database connection in `config.py`:
```python
class Config:
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:password@localhost/cyber_security_db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
```

5. Create database (if not already created):
```sql
CREATE DATABASE cyber_security_db;
```

6. Create tables:
```bash
python -c "from app import app; from extensions import db; app.app_context().push(); db.create_all(); print('tables created')"
```

## Train Phishing Model (Optimized)
This project is configured to use the optimized model file by default.

Run training:
```bash
python ml_models/train_phishing_model_optimized.py
```

Output model:
- `ml_models/phishing_model_optimized.pkl`

## Run Application
```bash
python app.py
```

Default local URL:
- `http://127.0.0.1:5000/`

## Main Routes
Page routes:
- `/` Home
- `/register` Register page
- `/login` Login page
- `/dashboard` User dashboard
- `/activity` Activity simulation page
- `/url-scan` URL phishing scan page (login required)
- `/admin/dashboard` Admin dashboard

API routes:
- `POST /api/register`
- `POST /api/login`
- `POST /api/log-action`
- `POST /api/log-event`
- `POST /api/scan-url` (login required)
- `GET /api/admin/alerts`
- `GET /api/admin/users`

## URL Scan API Example
Request:
```http
POST /api/scan-url
Content-Type: application/json

{
  "url": "https://www.google.com"
}
```

Response shape:
```json
{
  "prediction": "SAFE",
  "confidence": 0.84,
  "phishing_probability": 0.16,
  "phishing_threshold": 0.60,
  "normalized_url": "https://www.google.com/",
  "features": {}
}
```

## Notes
- `services/phishing_detector.py` is currently set to use:
  - `ml_models/phishing_model_optimized.pkl`
- Original large model/training script are excluded in `.gitignore`:
  - `ml_models/train_phishing_model.py`
  - `ml_models/phishing_model.pkl`

## Author
Angshul Arkarup
