from __future__ import annotations

from typing import Any, Mapping

import pandas as pd


DIRECT_FIELD_MAP: dict[str, tuple[str, ...]] = {
    "Destination_Port": (
        "destination_port",
        "Destination Port",
        "Destination_Port",
        "dest_port",
    ),
    "Flow_Duration": (
        "flow_duration",
        "Flow Duration",
        "Duration",
        "duration",
    ),
    "Total_Fwd_Packets": ("total_fwd_packets", "Total Fwd Packets"),
    "Total_Backward_Packets": ("total_backward_packets", "Total Backward Packets"),
    "Total_Length_of_Fwd_Packets": (
        "total_length_fwd_packets",
        "Total Length of Fwd Packets",
    ),
    "Total_Length_of_Bwd_Packets": (
        "total_length_bwd_packets",
        "Total Length of Bwd Packets",
    ),
    "Flow_Bytes_s": ("flow_bytes_s", "Flow Bytes/s", "Flow_Bytess"),
    "Flow_Packets_s": ("flow_packets_s", "Flow Packets/s", "Flow_Packetss"),
    "Fwd_Packets_s": ("fwd_packets_s", "Fwd Packets/s"),
    "Bwd_Packets_s": ("bwd_packets_s", "Bwd Packets/s"),
}

DEFAULTS: dict[str, float] = {
    "missing_numeric_feature": 0.0,
}


def _normalize(name: str) -> str:
    return name.strip().lower().replace(" ", "_").replace("/", "_").replace("-", "_")


def map_siem_alert(alert: Mapping[str, Any], feature_names: list[str]) -> pd.DataFrame:
    """Map a SIEM payload to the model schema; unmapped features use 0.0."""
    flattened: dict[str, Any] = dict(alert)
    for section in ("source", "network", "features", "enrichment"):
        nested = alert.get(section)
        if isinstance(nested, Mapping):
            flattened.update(nested)

    normalized = {_normalize(str(key)): value for key, value in flattened.items()}
    row: dict[str, float] = {}

    for feature in feature_names:
        alias_names = DIRECT_FIELD_MAP.get(feature)
        if alias_names is None:
            alias_names = (
                feature,
                feature.replace("_", " "),
                feature.lower(),
            )

        value: Any = None
        for alias in alias_names:
            candidate = normalized.get(_normalize(alias))
            if candidate is not None:
                value = candidate
                break

        try:
            row[feature] = float(value)
        except (TypeError, ValueError):
            row[feature] = DEFAULTS["missing_numeric_feature"]

    return pd.DataFrame([row], columns=feature_names)
