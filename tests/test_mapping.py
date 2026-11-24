from __future__ import annotations

from api.mapping import map_siem_alert


def test_mapping_maps_destination_port_and_defaults_missing_features() -> None:
    alert = {
        "destination_port": 22,
        "features": {"Duration": 12.5},
        "source": {"ip": "198.51.100.10"},
    }
    row = map_siem_alert(alert, ["Destination_Port", "Flow_Duration", "Idle_Max"])

    assert row["Destination_Port"].iloc[0] == 22.0
    assert row["Flow_Duration"].iloc[0] == 12.5
    assert row["Idle_Max"].iloc[0] == 0.0
