from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import joblib
import numpy as np
import pandas as pd
import shap
from api.mapping import map_siem_alert


MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "best_model.joblib"


def load_bundle() -> dict[str, Any]:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"No trained model at {MODEL_PATH}. Run: python -m ml.train"
        )
    bundle = joblib.load(MODEL_PATH)
    if not isinstance(bundle, dict) or "model" not in bundle:
        raise ValueError("Invalid model bundle.")
    return bundle


def alert_to_row(alert: Mapping[str, Any], feature_names: list[str]) -> pd.DataFrame:
    return map_siem_alert(alert, feature_names)


def shap_top_features(model: Any, row: pd.DataFrame, feature_names: list[str], limit: int = 5) -> list[dict[str, float | str]]:
    estimator = model.named_steps["classifier"] if hasattr(model, "named_steps") else model
    if hasattr(model, "named_steps") and "imputer" in model.named_steps:
        transformed = model.named_steps["imputer"].transform(row)
        if "scaler" in model.named_steps:
            transformed = model.named_steps["scaler"].transform(transformed)
    else:
        transformed = row

    explainer = shap.TreeExplainer(estimator)
    values = explainer.shap_values(transformed)
    matrix = np.asarray(values)
    if matrix.ndim == 3:
        matrix = matrix[:, :, 1]
    vector = matrix[0] if matrix.ndim == 2 else matrix
    ranked = np.argsort(np.abs(vector))[::-1][:limit]
    return [
        {"feature": feature_names[int(index)], "shap_value": float(vector[int(index)])}
        for index in ranked
    ]


def score(alert: Mapping[str, Any]) -> dict[str, Any]:
    bundle = load_bundle()
    model = bundle["model"]
    feature_names = list(bundle["feature_names"])
    row = alert_to_row(alert, feature_names)

    probability = float(model.predict_proba(row)[0][1])
    risk = round(probability * 100.0, 2)
    return {
        "risk": risk,
        "label": "malicious" if probability >= 0.5 else "benign",
        "probability": probability,
        "top_features": shap_top_features(model, row, feature_names),
        "model": bundle["model_name"],
    }
