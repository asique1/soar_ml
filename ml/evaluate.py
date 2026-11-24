from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from ml.data_loader import day_based_split, load_dataset_with_days
from ml.train import build_models


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
MODEL_PATH = ROOT / "models" / "best_model.joblib"
SAMPLE_SIZE = 100_000
RANDOM_STATE = 42


def metrics_for(
    model: Any,
    x_train: pd.DataFrame,
    y_train: pd.Series,
    x_test: pd.DataFrame,
    y_test: pd.Series,
) -> dict[str, float]:
    train_predictions = model.predict(x_train)
    test_predictions = model.predict(x_test)
    probabilities = model.predict_proba(x_test)[:, 1]
    return {
        "precision": float(precision_score(y_test, test_predictions, zero_division=0)),
        "recall": float(recall_score(y_test, test_predictions, zero_division=0)),
        "f1": float(f1_score(y_test, test_predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "train_f1": float(f1_score(y_train, train_predictions, zero_division=0)),
        "train_test_f1_gap": float(
            f1_score(y_train, train_predictions, zero_division=0)
            - f1_score(y_test, test_predictions, zero_division=0)
        ),
    }


def _sample_data() -> tuple[pd.DataFrame, pd.Series, pd.Series, int]:
    x, y, days = load_dataset_with_days()
    dataset_rows = len(x)
    if len(x) <= SAMPLE_SIZE:
        return x, y, days, dataset_rows
    sampled_x, _, sampled_y, _, sampled_days, _ = train_test_split(
        x,
        y,
        days,
        train_size=SAMPLE_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )
    return sampled_x, sampled_y, sampled_days, dataset_rows


def _write_shap_summary(model: Any, x_test: pd.DataFrame) -> None:
    sample_count = min(300, len(x_test))
    sample = x_test.sample(n=sample_count, random_state=RANDOM_STATE)
    pipeline = model
    estimator = pipeline.named_steps["classifier"]
    transformed = pipeline.named_steps["imputer"].transform(sample)

    explainer = shap.TreeExplainer(estimator)
    values = explainer.shap_values(transformed)
    if isinstance(values, list):
        values = values[1]
    values = np.asarray(values)
    if values.ndim == 3:
        values = values[:, :, 1]

    shap.summary_plot(
        values,
        sample,
        feature_names=list(sample.columns),
        max_display=20,
        show=False,
    )
    plt.tight_layout()
    plt.savefig(RESULTS / "shap_summary.png", dpi=160, bbox_inches="tight")
    plt.close()


def _baseline_comparison(
    model: Any,
    x_test: pd.DataFrame,
    y_test: pd.Series,
) -> list[dict[str, Any]]:
    suspicious_ports = {21, 22, 23, 3389, 4444, 8080}
    rule_predictions_list: list[int] = []
    rule_started = time.perf_counter()
    for port in x_test["Destination_Port"].to_numpy():
        rule_predictions_list.append(int(port) in suspicious_ports)
    rule_elapsed = time.perf_counter() - rule_started
    rule_predictions = np.asarray(rule_predictions_list, dtype=np.int64)

    ml_elapsed = 0.0
    probabilities = np.empty(len(x_test), dtype=float)
    for index in range(len(x_test)):
        started = time.perf_counter()
        probabilities[index] = model.predict_proba(x_test.iloc[[index]])[0, 1]
        ml_elapsed += time.perf_counter() - started
    ml_auto = probabilities < 0.7
    ml_auto_predictions = probabilities >= 0.5

    return [
        {
            "strategy": "fixed_rules",
            "alerts_evaluated": len(y_test),
            "auto_handled_share": 1.0,
            "false_negatives": int(((rule_predictions == 0) & (y_test == 1)).sum()),
            "avg_pipeline_seconds_per_alert": rule_elapsed / len(y_test),
            "method": "Malicious iff Destination_Port is one of 21,22,23,3389,4444,8080; all alerts auto-decided.",
            "measurement_scope": "Per-alert local rule evaluation only; excludes enrichment, persistence, actions, and analyst resolution.",
        },
        {
            "strategy": "ml_triage",
            "alerts_evaluated": len(y_test),
            "auto_handled_share": float(ml_auto.mean()),
            "false_negatives": int(
                ((ml_auto_predictions == 0) & (y_test.to_numpy() == 1)).sum()
            ),
            "avg_pipeline_seconds_per_alert": ml_elapsed / len(y_test),
            "method": "Use 0.50 probability for label; risk >=70 requires analyst approval and is not auto-handled.",
            "measurement_scope": "Per-alert local model inference only; excludes enrichment, persistence, actions, and analyst resolution.",
        },
    ]


def run_evaluation() -> dict[str, Any]:
    RESULTS.mkdir(parents=True, exist_ok=True)
    features, labels, days, dataset_rows = _sample_data()
    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=labels,
    )

    metric_rows: list[dict[str, Any]] = []
    fitted_models: dict[str, Any] = {}
    random_metrics: dict[str, dict[str, float]] = {}
    for model_name, model in build_models(RANDOM_STATE).items():
        model.fit(x_train, y_train)
        fitted_models[model_name] = model
        scores = metrics_for(model, x_train, y_train, x_test, y_test)
        random_metrics[model_name] = scores
        metric_rows.append({
            "split": "stratified_random_80_20",
            "model": model_name,
            "train_rows": len(x_train),
            "test_rows": len(x_test),
            **scores,
        })

    split = day_based_split(features, labels, days)
    day_metrics: dict[str, dict[str, float]] = {}
    if split is not None:
        day_train_x, day_test_x, day_train_y, day_test_y = split
        for model_name, model in build_models(RANDOM_STATE).items():
            model.fit(day_train_x, day_train_y)
            scores = metrics_for(
                model,
                day_train_x,
                day_train_y,
                day_test_x,
                day_test_y,
            )
            day_metrics[model_name] = scores
            metric_rows.append({
                "split": "mon_wed_train_thu_fri_test",
                "model": model_name,
                "train_rows": len(day_train_x),
                "test_rows": len(day_test_x),
                **scores,
            })

    metrics_frame = pd.DataFrame(metric_rows)
    metrics_frame.to_csv(RESULTS / "metrics.csv", index=False)
    best_name = max(random_metrics, key=lambda name: random_metrics[name]["f1"])
    best_model = fitted_models[best_name]
    predictions = best_model.predict(x_test)
    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])
    display = ConfusionMatrixDisplay(matrix, display_labels=["Benign", "Malicious"])
    display.plot(cmap="Blues", values_format="d")
    plt.title(f"Best model: {best_name} (stratified held-out test)")
    plt.tight_layout()
    plt.savefig(RESULTS / "confusion_matrix.png", dpi=160)
    plt.close()
    _write_shap_summary(best_model, x_test)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": best_model,
        "feature_names": list(features.columns),
        "model_name": best_name,
        "target_names": ["benign", "malicious"],
    }, MODEL_PATH)

    baseline = _baseline_comparison(best_model, x_test, y_test)
    pd.DataFrame(baseline).to_csv(RESULTS / "baseline_comparison.csv", index=False)

    train_hashes = pd.util.hash_pandas_object(x_train, index=False)
    test_hashes = pd.util.hash_pandas_object(x_test, index=False)
    duplicate_count = len(set(train_hashes.tolist()).intersection(test_hashes.tolist()))
    correlations = features.assign(_label=labels.to_numpy()).corr(numeric_only=True)["_label"]
    top_correlations = correlations.drop("_label").abs().sort_values(ascending=False).head(10)
    report = {
        "dataset": "CIC-IDS2017",
        "cleaned_dataset_rows": dataset_rows,
        "sample_rows": len(features),
        "feature_count": len(features.columns),
        "random_split": {
            "train_rows": len(x_train),
            "test_rows": len(x_test),
            "duplicates_across_splits": duplicate_count,
            "top_absolute_label_correlations": {
                name: float(value) for name, value in top_correlations.items()
            },
            "models": random_metrics,
            "best_model": best_name,
        },
        "day_based_split": day_metrics or None,
        "baseline_comparison": baseline,
    }
    (RESULTS / "evaluation_report.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    run_evaluation()
