from __future__ import annotations

import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from ml.score import score, shap_top_features

from ml.data_loader import binary_labels, load_dataset
from ml.score import alert_to_row


def test_binary_labels_normalizes_benign_and_malicious() -> None:
    labels = pd.Series(["BENIGN", "Bot", "BENIGN", "Bot"])
    assert binary_labels(labels).tolist() == [0, 1, 0, 1]


def test_alert_to_row_maps_known_features(tmp_path) -> None:
    row = alert_to_row(
        {"source": {"ip": "198.51.100.10"}, "risk": 80, "Duration": 12},
        ["Destination Port", "Duration"],
    )
    assert row["Duration"].iloc[0] == 12
    assert row["Destination Port"].iloc[0] == 0.0


def test_load_dataset_accepts_csv(tmp_path) -> None:
    rows = 40
    frame = pd.DataFrame({
        "Destination Port": [22, 3389] * (rows // 2),
        "Flow Duration": list(range(rows)),
        "Label": ["BENIGN", "Bot"] * (rows // 2),
    })
    path = tmp_path / "alerts.csv"
    frame.to_csv(path, index=False)

    features, labels = load_dataset([path])
    assert len(features) == 40
    assert set(labels.unique()) == {0, 1}


def test_unknown_label_raises(tmp_path) -> None:
    labels = pd.Series(["BENIGN", "Unknown Attack"])
    with pytest.raises(ValueError, match="Unknown CIC-IDS2017 label"):
        binary_labels(labels)


def test_tree_explainer_returns_top_features() -> None:
    frame = pd.DataFrame({
        "Duration": [1.0, 2.0, 8.0, 9.0],
        "Destination Port": [22, 22, 3389, 3389],
        "_target": [0, 0, 1, 1],
    })
    features = frame.drop(columns=["_target"])
    model = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(n_estimators=20, random_state=42)),
    ])
    model.fit(features, frame["_target"])

    top_features = shap_top_features(model, features.iloc[[0]], list(features.columns), limit=2)
    assert len(top_features) == 2
    assert set(top_features[0]) == {"feature", "shap_value"}


def test_score_returns_risk_label_and_shap(monkeypatch) -> None:
    features = pd.DataFrame({
        "Duration": [1.0, 2.0, 8.0, 9.0],
        "Destination_Port": [22, 22, 3389, 3389],
    })
    labels = pd.Series([0, 0, 1, 1])
    model = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(n_estimators=20, random_state=42)),
    ])
    model.fit(features, labels)
    monkeypatch.setattr(
        "ml.score.load_bundle",
        lambda: {
            "model": model,
            "feature_names": list(features.columns),
            "model_name": "test_forest",
        },
    )

    result = score({"Duration": 9.0, "destination_port": 3389})
    assert 0 <= result["risk"] <= 100
    assert result["label"] == "malicious"
    assert result["top_features"]
