from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from ml.data_loader import load_dataset


def run_eda(csv_paths: list[Path] | None = None) -> Path:
    features, labels = load_dataset(csv_paths)
    output = Path(__file__).resolve().parents[1] / "data" / "processed"
    output.mkdir(parents=True, exist_ok=True)

    summary = features.describe(include="all").T
    summary["missing_count"] = features.isna().sum()
    summary["missing_percent"] = features.isna().mean() * 100
    report = summary.to_csv()
    report_path = output / "eda_summary.csv"
    report_path.write_text(report, encoding="utf-8")

    class_counts = pd.DataFrame({"count": labels.value_counts().sort_index()})
    class_counts.to_csv(output / "class_distribution.csv")
    print(f"Rows: {len(features)}, features: {len(features.columns)}, classes: {labels.value_counts().to_dict()}")
    return report_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", nargs="*", type=Path)
    args = parser.parse_args()
    print(run_eda(args.csv or None))
