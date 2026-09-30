from __future__ import annotations

from typing import Any

from logistics_key_drill.leaked_key_drill import DrillRequest, run_drill


class RecordingControlPlane:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    def report_suspected_compromise(self, key_id: str, *, confirmed_leak: bool) -> dict[str, str]:
        self.calls.append(("report", (key_id, confirmed_leak)))
        return {"status": "recorded"}

    def search_logs(self) -> dict[str, list[dict[str, str]]]:
        self.calls.append(("search", None))
        return {"records": [{"service": "dispatch"}, {"service": "pod-reader"}]}

    def create_drill_key(self, *, project_id: str, idempotency_key: str) -> dict[str, str]:
        self.calls.append(("create", (project_id, idempotency_key)))
        return {"key_id": "key-drill-17"}

    def rotate_drill_key(self, key_id: str, *, idempotency_key: str) -> dict[str, str]:
        self.calls.append(("rotate", (key_id, idempotency_key)))
        return {"id": key_id}

    def revoke_drill_key(self, key_id: str) -> dict[str, str]:
        self.calls.append(("revoke", key_id))
        return {"id": key_id}


def test_drill_reports_then_rotates_temporary_key_and_confirms_blast_radius() -> None:
    request = DrillRequest.model_validate(
        {
            "drill_id": "3d6fce9e-b96b-4e17-a184-cce10fdfc167",
            "compromised_key_id": "key-live-42",
            "project_id": "logistics-prod",
            "exposure_started_at": "2026-09-25T08:00:00Z",
            "exposure_ended_at": "2026-09-25T08:20:00Z",
            "shipment_events": [
                {
                    "shipment_id": "SHP-100",
                    "event": "out_for_delivery",
                    "occurred_at": "2026-09-25T08:04:00Z",
                },
                {
                    "shipment_id": "SHP-101",
                    "event": "delivered",
                    "occurred_at": "2026-09-25T08:11:00Z",
                },
            ],
            "proofs": [
                {
                    "shipment_id": "SHP-101",
                    "object_key": "proofs/SHP-101/photo.jpg",
                    "sha256": "a" * 64,
                }
            ],
            "exceptions": [
                {
                    "shipment_id": "SHP-100",
                    "category": "address_review",
                    "detail": "dispatcher reviewed destination",
                }
            ],
        }
    )
    control_plane = RecordingControlPlane()

    result = run_drill(request, control_plane)

    assert result.state == "confirmed"
    assert result.blast_radius.shipment_ids == ["SHP-100", "SHP-101"]
    assert result.blast_radius.proof_object_keys == ["proofs/SHP-101/photo.jpg"]
    assert result.blast_radius.exception_count == 1
    assert result.blast_radius.log_records_examined == 2
    assert [name for name, _ in control_plane.calls] == [
        "report",
        "search",
        "create",
        "rotate",
        "revoke",
    ]
    assert control_plane.calls[0][1] == ("key-live-42", True)
    assert control_plane.calls[3][1][0] == "key-drill-17"
    assert control_plane.calls[4][1] == "key-drill-17"


def test_drill_revokes_temporary_key_when_rotation_fails() -> None:
    class FailingRotationControlPlane(RecordingControlPlane):
        def rotate_drill_key(self, key_id: str, *, idempotency_key: str) -> dict[str, str]:
            super().rotate_drill_key(key_id, idempotency_key=idempotency_key)
            raise RuntimeError("rotation failed")

    request = DrillRequest.model_validate(
        {
            "drill_id": "3d6fce9e-b96b-4e17-a184-cce10fdfc167",
            "compromised_key_id": "key-live-42",
            "project_id": "logistics-prod",
            "exposure_started_at": "2026-09-25T08:00:00Z",
            "exposure_ended_at": "2026-09-25T08:20:00Z",
            "shipment_events": [],
            "proofs": [],
            "exceptions": [],
        }
    )
    control_plane = FailingRotationControlPlane()

    try:
        run_drill(request, control_plane)
    except RuntimeError as exc:
        assert str(exc) == "rotation failed"
    else:
        raise AssertionError("rotation failure was not raised")

    assert control_plane.calls[-1] == ("revoke", "key-drill-17")
