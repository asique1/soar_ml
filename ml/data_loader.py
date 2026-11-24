from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import re


TARGET_NAMES = ("Label", "label", "attack_cat", "class", "Category")
LABELS = {
    "BENIGN": 0,
    "Bot": 1,
    "DDoS": 1,
    "DoS GoldenEye": 1,
    "DoS Hulk": 1,
    "DoS Slowhttptest": 1,
    "DoS slowloris": 1,
    "FTP-Patator": 1,
    "Heartbleed": 1,
    "Infiltration": 1,
    "PortScan": 1,
    "SSH-Patator": 1,
    "Web Attack - Brute Force": 1,
    "Web Attack - Sql Injection": 1,
    "Web Attack - XSS": 1,
}


def find_csv_files(data_dir: Path) -> list[Path]:
    if not data_dir.exists():
        return []
    return sorted(
        path for path in data_dir.rglob("*")
        if path.suffix.lower() == ".csv" and path.name != "demo_dataset.csv"
    )


def clean_column_name(name: str) -> str:
    cleaned = re.sub(r"\s+", "_", str(name).strip())
    cleaned = cleaned.replace("/", "_").replace("-", "_")
    return cleaned


def infer_target(frame: pd.DataFrame) -> str:
    for name in TARGET_NAMES:
        if name in frame.columns:
            return name
    raise ValueError(
        "No target column found. Use Label, label, attack_cat, class, or Category."
    )


def binary_labels(series: pd.Series) -> pd.Series:
    text = series.astype("string").str.strip()
    text = text.str.replace("\ufffd", "-", regex=False)
    labels: dict[str, int] = {}
    for raw_label in text.dropna().unique():
        normalized = str(raw_label)
        if normalized not in LABELS:
            raise ValueError(f"Unknown CIC-IDS2017 label: {normalized!r}")
        labels[normalized] = LABELS[normalized]
    try:
        return text.map(labels).astype("int64")
    except (TypeError, ValueError) as exc:
        raise ValueError("Dataset contains an invalid or missing label") from exc


def load_dataset(csv_paths: list[Path] | None = None) -> tuple[pd.DataFrame, pd.Series]:
    data_dir = Path(__file__).resolve().parents[1] / "data" / "raw"
    paths = csv_paths or find_csv_files(data_dir)
    if not paths:
        raise FileNotFoundError(
            f"No CSV data found in {data_dir}. Add CIC-IDS2017 or UNSW-NB15 CSV files, "
            "or run `python -m ml.create_demo_data` to create a local validation dataset."
        )

    frames: list[pd.DataFrame] = []
    for path in paths:
        frame = pd.read_csv(path, low_memory=False)
        frame["_source_day"] = cic_day_from_filename(path.name)
        frames.append(frame)
    frame = pd.concat(frames, ignore_index=True)
    frame.columns = [clean_column_name(column) for column in frame.columns]

    target = infer_target(frame)
    labels = binary_labels(frame[target])
    features = frame.drop(columns=[target, "_source_day"]).select_dtypes(include=[np.number]).copy()
    features = features.replace([np.inf, -np.inf], np.nan)
    features = features.loc[:, features.notna().sum() > 0]

    feature_frame = features.copy()
    feature_frame["_label"] = labels.to_numpy()
    feature_frame = feature_frame.replace([np.inf, -np.inf], np.nan)
    feature_frame = feature_frame.dropna()
    feature_columns = [column for column in feature_frame.columns if column != "_label"]
    feature_frame = feature_frame.drop_duplicates(subset=feature_columns, keep=False)
    labels = feature_frame["_label"].astype("int64")
    features = feature_frame.drop(columns=["_label"])

    if labels.nunique() != 2:
        raise ValueError("The cleaned dataset must contain both benign and malicious classes.")
    if len(features) < 20:
        raise ValueError("The cleaned dataset is too small for a train/test split.")

    features.columns = [str(column).strip() for column in features.columns]
    return features, labels


def cic_day_from_filename(filename: str) -> str:
    lowered = filename.lower()
    if "monday" in lowered:
        return "Monday"
    if "tuesday" in lowered:
        return "Tuesday"
    if "wednesday" in lowered:
        return "Wednesday"
    if "thursday" in lowered:
        return "Thursday"
    if "friday" in lowered:
        return "Friday"
    return "Unknown"


def load_dataset_with_days(csv_paths: list[Path] | None = None) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
    data_dir = Path(__file__).resolve().parents[1] / "data" / "raw"
    paths = csv_paths or find_csv_files(data_dir)
    if not paths:
        raise FileNotFoundError(
            f"No CIC-IDS2017 CSV data found in {data_dir}. Place real day CSV files in data/raw/."
        )

    frames: list[pd.DataFrame] = []
    for path in paths:
        frame = pd.read_csv(path, low_memory=False)
        frame["_source_day"] = cic_day_from_filename(path.name)
        frames.append(frame)
    frame = pd.concat(frames, ignore_index=True)
    frame.columns = [clean_column_name(column) for column in frame.columns]

    target = infer_target(frame)
    labels = binary_labels(frame[target])
    features = frame.drop(columns=[target, "_source_day"]).select_dtypes(include=[np.number]).copy()
    features = features.replace([np.inf, -np.inf], np.nan)

    day = frame["_source_day"].loc[features.index]
    combined = features.copy()
    combined["_label"] = labels.to_numpy()
    combined["_source_day"] = day.to_numpy()
    combined = combined.dropna()
    feature_columns = [
        column for column in combined.columns
        if column not in {"_label", "_source_day"}
    ]
    combined = combined.drop_duplicates(subset=feature_columns, keep=False)

    labels = combined["_label"].astype("int64")
    day = combined["_source_day"]
    features = combined.drop(columns=["_label", "_source_day"])

    if labels.nunique() != 2:
        raise ValueError("The cleaned dataset must contain both benign and malicious classes.")
    if len(features) < 20:
        raise ValueError("The cleaned dataset is too small for a train/test split.")
    return features, labels, day


def day_based_split(
    features: pd.DataFrame,
    labels: pd.Series,
    days: pd.Series,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series] | None:
    train_days = {"Monday", "Tuesday", "Wednesday"}
    test_days = {"Thursday", "Friday"}
    if not set(days.unique()).issuperset(train_days | test_days):
        return None
    train_mask = days.isin(train_days)
    test_mask = days.isin(test_days)
    if not train_mask.any() or not test_mask.any():
        return None
    if labels.loc[train_mask].nunique() != 2 or labels.loc[test_mask].nunique() != 2:
        return None
    return (
        features.loc[train_mask],
        features.loc[test_mask],
        labels.loc[train_mask],
        labels.loc[test_mask],
    )


def save_processed(features: pd.DataFrame, labels: pd.Series) -> Path:
    output = Path(__file__).resolve().parents[1] / "data" / "processed"
    output.mkdir(parents=True, exist_ok=True)
    frame = features.copy()
    frame["target"] = labels.to_numpy()
    path = output / "cleaned_dataset.csv"
    frame.to_csv(path, index=False)
    return path
