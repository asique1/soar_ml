from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import matplotlib.pyplot as plt
import pandas as pd
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import ConfusionMatrixDisplay, classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ml.data_loader import load_dataset, save_processed


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "best_model.joblib"


def build_models(random_state: int) -> dict[str, Pipeline]:
    logistic = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=random_state)),
    ])
    forest = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(
            n_estimators=200, class_weight="balanced", random_state=random_state, n_jobs=-1
        )),
    ])

    try:
        from xgboost import XGBClassifier
        xgboost = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", XGBClassifier(
                n_estimators=200, max_depth=6, learning_rate=0.1, subsample=0.9,
                colsample_bytree=0.9, eval_metric="logloss", random_state=random_state,
                n_jobs=-1,
            )),
        ])
    except ImportError:
        xgboost = forest

    return {"logistic_regression": logistic, "random_forest": forest, "xgboost": xgboost}


def evaluate_model(name: str, model: Pipeline, x_test: pd.DataFrame, y_test: pd.Series) -> dict[str, Any]:
    probabilities = model.predict_proba(x_test)[:, 1]
    predictions = model.predict(x_test)
    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)
    display = ConfusionMatrixDisplay(confusion_matrix(y_test, predictions), display_labels=["Benign", "Malicious"])
    display.plot(cmap="Blues", values_format="d")
    plt.title(f"{name} confusion matrix")
    plt.tight_layout()
    plt.savefig(ROOT / "data" / "processed" / f"{name}_confusion_matrix.png", dpi=150)
    plt.close()

    return {
        "precision": report["weighted avg"]["precision"],
        "recall": report["weighted avg"]["recall"],
        "f1": report["weighted avg"]["f1-score"],
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
    }


def train(csv_paths: list[Path] | None = None) -> dict[str, Any]:
    features, labels = load_dataset(csv_paths)
    processed_path = save_processed(features, labels)
    x_train, x_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.2, random_state=42, stratify=labels
    )

    results: dict[str, dict[str, Any]] = {}
    fitted: dict[str, Pipeline] = {}
    for name, model in build_models(42).items():
        model.fit(x_train, y_train)
        fitted[name] = model
        results[name] = evaluate_model(name, model, x_test, y_test)

    best_name = max(results, key=lambda name: results[name]["f1"])
    best_model = fitted[best_name]

    bundle = {
        "model": best_model,
        "feature_names": list(features.columns),
        "model_name": best_name,
        "target_names": ["benign", "malicious"],
    }
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, MODEL_PATH)

    report = {
        "processed_dataset": str(processed_path),
        "training_rows": len(x_train),
        "test_rows": len(x_test),
        "feature_count": len(features.columns),
        "models": results,
        "best_model": best_name,
        "model_path": str(MODEL_PATH),
    }
    report_path = ROOT / "data" / "processed" / "training_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(description="Train SOAR ML models.")
    argument_parser.add_argument("--csv", nargs="*", type=Path, help="Optional CSV paths.")
    return argument_parser


if __name__ == "__main__":
    args = parser().parse_args()
    print(json.dumps(train(args.csv or None), indent=2))
