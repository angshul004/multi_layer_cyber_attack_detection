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
git clone <repo-url>
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

4. Create a `.env` file (or copy from `.env.example`) and set:
```env
SECRET_KEY=replace_with_a_strong_random_secret_key
DB_USER=your_mysql_user
DB_PASSWORD=your_mysql_password
DB_HOST=localhost
DB_NAME=cyber_security_db
```

5. Create database in mysql (if not already created):
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

My model's accuracy:
```bash
Test Accuracy: 0.8913
Test Precision (PHISHING): 0.9459
Test Recall (PHISHING): 0.6556
Test F1 (PHISHING): 0.7744
Confusion matrix:
[[77412  1173]
 [10775 20510]]
```

## Run Application
```bash
python app.py
```

Default local URL:
- `http://127.0.0.1:5000/`

Route behavior note:
- If a user is already logged in, opening `/` redirects to their dashboard.
- `/register` currently renders the same page as `/` (shared registration UI).

## Main Routes
Page routes:
- `/` Home
- `/register` Register page
- `/login` Login page
- `/dashboard` User dashboard
- `/activity` Activity simulation page
- `/url-scan` URL phishing scan page 
- `/admin/dashboard` Admin dashboard

API routes:
- `POST /api/register`
- `POST /api/login`
- `POST /api/log-action`
- `POST /api/scan-url` 
- `GET /api/admin/alerts`
- `GET /api/admin/users`
- `GET /api/admin/user/<id>`
- `GET /api/admin/user/<id>/timeline`
- `POST /api/admin/user/<id>/reset-security`

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

## Risk Scoring
Risk score is stored per user in `risk_scores.score` and updated by backend services.

### Current calculation rules
- `FAILED_LOGIN` -> `+10`
- `SECURITY_ALERT` (after repeated failed logins) -> `+30`
- Behavior anomaly detected (more than 10 actions in the last 1 minute) -> `+20`

### Event types involved
- `FAILED_LOGIN`
- `SUCCESSFUL_LOGIN` (logged, but does not increase score)
- `SECURITY_ALERT` (logged during brute-force detection flow)
- `API_CALL` and `PAGE_ACCESS` (counted for behavior-anomaly checks)
- `URL_SCAN` (logged only; currently does not change risk score)

### Notes
- Behavior anomaly currently excludes these event types from action count:
  - `SUCCESSFUL_LOGIN`
  - `FAILED_LOGIN`
  - `SECURITY_ALERT`
  - `URL_SCAN`
- URL scanning endpoint records events in `event_logs` but does not update risk score.

## Author
Angshul Arkarup
