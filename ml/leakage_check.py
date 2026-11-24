from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ml.data_loader import day_based_split, load_dataset, load_dataset_with_days


ROOT = Path(__file__).resolve().parents[1]


def run_check(sample_size: int = 100_000) -> dict[str, object]:
    features, labels = load_dataset()
    if len(features) > sample_size:
        features, _, labels, _ = train_test_split(
            features,
            labels,
            train_size=sample_size,
            random_state=42,
            stratify=labels,
        )

    train_x, test_x, train_y, test_y = train_test_split(
        features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    duplicates_across_split = int(
        pd.MultiIndex.from_frame(train_x).intersection(
            pd.MultiIndex.from_frame(test_x)
        ).size
    )

    correlations = features.assign(_label=labels.to_numpy()).corr(numeric_only=True)["_label"]
    correlated = (
        correlations.drop("_label")
        .abs()
        .sort_values(ascending=False)
        .head(10)
    )
    high_label_correlations = {
        name: round(float(value), 6)
        for name, value in correlated.items()
        if abs(float(value)) >= 0.8
    }

    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(
            max_iter=500,
            class_weight="balanced",
            random_state=42,
        )),
    ])
    pipeline.fit(train_x, train_y)
    train_f1 = float(f1_score(train_y, pipeline.predict(train_x), zero_division=0))
    test_f1 = float(f1_score(test_y, pipeline.predict(test_x), zero_division=0))

    day_report: dict[str, object] | None = None
    day_features, day_labels, days = load_dataset_with_days()
    if len(day_features) > sample_size:
        day_features, _, day_labels, _, days, _ = train_test_split(
            day_features,
            day_labels,
            days,
            train_size=sample_size,
            random_state=42,
            stratify=day_labels,
        )
    day_split = day_based_split(day_features, day_labels, days)
    if day_split is not None:
        day_train_x, day_test_x, day_train_y, day_test_y = day_split
        day_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(
                max_iter=500,
                class_weight="balanced",
                random_state=42,
            )),
        ])
        day_pipeline.fit(day_train_x, day_train_y)
        day_train_f1 = float(
            f1_score(day_train_y, day_pipeline.predict(day_train_x), zero_division=0)
        )
        day_test_f1 = float(
            f1_score(day_test_y, day_pipeline.predict(day_test_x), zero_division=0)
        )
        day_duplicates = int(
            pd.MultiIndex.from_frame(day_train_x).intersection(
                pd.MultiIndex.from_frame(day_test_x)
            ).size
        )
        day_report = {
            "train_rows_mon_wed": len(day_train_x),
            "test_rows_thu_fri": len(day_test_x),
            "duplicates_across_day_split": day_duplicates,
            "logistic_regression_train_f1": day_train_f1,
            "logistic_regression_test_f1": day_test_f1,
            "logistic_regression_train_test_f1_gap": day_train_f1 - day_test_f1,
        }

    report = {
        "sample_rows": len(features),
        "train_rows": len(train_x),
        "test_rows": len(test_x),
        "duplicate_feature_vectors_in_dataset": int(features.duplicated().sum()),
        "duplicates_across_train_test": duplicates_across_split,
        "top_label_correlations": {
            name: round(float(value), 6)
            for name, value in correlated.items()
        },
        "features_with_absolute_correlation_ge_0.8": high_label_correlations,
        "logistic_regression_train_f1": train_f1,
        "logistic_regression_test_f1": test_f1,
        "logistic_regression_train_test_f1_gap": train_f1 - test_f1,
        "day_based_split": day_report,
    }

    output = ROOT / "data" / "processed" / "leakage_report.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    run_check()
