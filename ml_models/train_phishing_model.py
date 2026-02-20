#not optimized version, for reference only. See train_phishing_model_optimized.py for the optimized version.
from __future__ import annotations

import csv
import os
import pickle
import sys

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_recall_curve,
        precision_score,
        recall_score,
    )
    from sklearn.model_selection import train_test_split
except ImportError:
    print("scikit-learn is not installed. Please install it with: pip install scikit-learn")
    sys.exit(1)

from feature_extractor import FEATURE_NAMES, extract_features


DATASET_PATH = os.path.join(os.path.dirname(__file__), "phishing_site_urls.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.pkl")
MIN_PHISHING_PRECISION = 0.95
MIN_THRESHOLD_FLOOR = 0.60
MAX_THRESHOLD_CAP = 0.80


def load_dataset(path: str):
    features = []
    labels = []
    total_rows = 0
    skipped_rows = 0

    with open(path, "r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            total_rows += 1
            normalized_row = {(k or "").strip().lower(): v for k, v in row.items()}
            url = (normalized_row.get("url") or "").strip()
            label = (normalized_row.get("label") or "").strip().lower()

            if not url or label not in {"good", "bad"}:
                skipped_rows += 1
                continue

            features.append(extract_features(url))
            labels.append(1 if label == "bad" else 0)

    return features, labels, total_rows, skipped_rows


def pick_threshold(y_true, phishing_probs, min_precision=MIN_PHISHING_PRECISION):
    precisions, recalls, thresholds = precision_recall_curve(y_true, phishing_probs)
    # precision_recall_curve returns one extra precision/recall element.
    if len(thresholds) == 0:
        return 0.5

    best_threshold = 0.5
    best_f1 = -1.0

    for idx, threshold in enumerate(thresholds):
        precision = precisions[idx]
        recall = recalls[idx]
        if precision < min_precision:
            continue
        f1 = 0.0 if (precision + recall) == 0 else (2 * precision * recall) / (precision + recall)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = float(threshold)

    if best_f1 >= 0:
        best_threshold = max(best_threshold, MIN_THRESHOLD_FLOOR)
        best_threshold = min(best_threshold, MAX_THRESHOLD_CAP)
        return best_threshold

    # Fallback: choose threshold with highest F1 without precision constraint.
    for idx, threshold in enumerate(thresholds):
        precision = precisions[idx]
        recall = recalls[idx]
        f1 = 0.0 if (precision + recall) == 0 else (2 * precision * recall) / (precision + recall)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = float(threshold)

    best_threshold = max(best_threshold, MIN_THRESHOLD_FLOOR)
    best_threshold = min(best_threshold, MAX_THRESHOLD_CAP)
    return best_threshold


def main():
    if not os.path.exists(DATASET_PATH):
        print(f"Dataset not found at: {DATASET_PATH}")
        sys.exit(1)

    x, y, total_rows, skipped_rows = load_dataset(DATASET_PATH)

    if not x:
        print("No valid records found in dataset.")
        sys.exit(1)

    phishing_count = sum(y)
    safe_count = len(y) - phishing_count

    print(f"Total rows read: {total_rows}")
    print(f"Valid rows used: {len(y)}")
    print(f"Skipped rows: {skipped_rows}")
    print(f"Label counts -> SAFE(0): {safe_count}, PHISHING(1): {phishing_count}")

    x_train_full, x_test, y_train_full, y_test = train_test_split(
        x, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train samples: {len(x_train_full)}")
    print(f"Test samples: {len(x_test)}")

    x_fit, x_val, y_fit, y_val = train_test_split(
        x_train_full, y_train_full, test_size=0.2, random_state=42, stratify=y_train_full
    )
    print(f"Train (fit) samples: {len(x_fit)}")
    print(f"Validation samples: {len(x_val)}")

    model_name = "random_forest"
    model = RandomForestClassifier(
        n_estimators=350,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )
    model.fit(x_fit, y_fit)

    val_phishing_probs = model.predict_proba(x_val)[:, 1]
    threshold = pick_threshold(y_val, val_phishing_probs, min_precision=MIN_PHISHING_PRECISION)
    print(f"Tuned phishing threshold: {threshold:.4f}")

    model.fit(x_train_full, y_train_full)
    test_phishing_probs = model.predict_proba(x_test)[:, 1]
    y_pred = (test_phishing_probs >= threshold).astype(int)

    acc = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print(f"\nTest Accuracy: {acc:.4f}")
    print(f"Test Precision (PHISHING): {precision:.4f}")
    print(f"Test Recall (PHISHING): {recall:.4f}")
    print(f"Test F1 (PHISHING): {f1:.4f}")
    print("Confusion matrix:")
    print(cm)

    print(f"Model used: {model_name}")

    artifact = {
        "model": model,
        "model_name": model_name,
        "feature_names": FEATURE_NAMES,
        "phishing_threshold": float(threshold),
    }

    with open(MODEL_PATH, "wb") as model_file:
        pickle.dump(artifact, model_file)

    print(f"Model saved at: {MODEL_PATH}")


if __name__ == "__main__":
    main()
