from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


def create_demo_data(rows_per_class: int = 500) -> Path:
    rng = np.random.default_rng(42)
    benign = rng.normal(loc=0.0, scale=1.0, size=(rows_per_class, 4))
    malicious = rng.normal(loc=1.8, scale=1.2, size=(rows_per_class, 4))

    frame = pd.DataFrame(
        np.vstack([benign, malicious]),
        columns=["Duration", "Flow Bytes/s", "Flow Packets/s", "Destination Port"],
    )
    benign_port = rng.choice([22, 80, 443], rows_per_class)
    malicious_port = rng.choice([22, 3389, 4444], rows_per_class)
    frame["Destination Port"] = np.concatenate([benign_port, malicious_port])
    frame["Label"] = np.where(np.arange(len(frame)) < rows_per_class, "BENIGN", "Bot")

    output = Path(__file__).resolve().parents[1] / "data" / "raw" / "demo_dataset.csv"
    output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output, index=False)
    return output


if __name__ == "__main__":
    print(create_demo_data())
