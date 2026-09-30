from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from pydantic import BaseModel, Field


class ShipmentEvent(BaseModel):
    shipment_id: str
    event: str
    occurred_at: datetime


class ProofOfDelivery(BaseModel):
    shipment_id: str
    object_key: str
    sha256: str = Field(min_length=64, max_length=64)


class ShipmentException(BaseModel):
    shipment_id: str
    category: str
    detail: str


class DrillRequest(BaseModel):
    drill_id: UUID
    compromised_key_id: str
    project_id: str
    exposure_started_at: datetime
    exposure_ended_at: datetime
    shipment_events: list[ShipmentEvent]
    proofs: list[ProofOfDelivery]
    exceptions: list[ShipmentException]


class BlastRadius(BaseModel):
    shipment_ids: list[str]
    proof_object_keys: list[str]
    exception_count: int
    log_records_examined: int


class DrillResult(BaseModel):
    drill_id: UUID
    state: str
    temporary_key_id: str
    blast_radius: BlastRadius


class ControlPlane(Protocol):
    def report_suspected_compromise(self, key_id: str, *, confirmed_leak: bool) -> Any:
        raise AssertionError("protocol declaration")

    def search_logs(self) -> Any:
        raise AssertionError("protocol declaration")

    def create_drill_key(self, *, project_id: str, idempotency_key: str) -> Any:
        raise AssertionError("protocol declaration")

    def rotate_drill_key(self, key_id: str, *, idempotency_key: str) -> Any:
        raise AssertionError("protocol declaration")

    def revoke_drill_key(self, key_id: str) -> Any:
        raise AssertionError("protocol declaration")


def _log_records(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def run_drill(request: DrillRequest, infrai: ControlPlane) -> DrillResult:
    if request.exposure_ended_at < request.exposure_started_at:
        raise ValueError("exposure_ended_at must be on or after exposure_started_at")

    drill_token = str(request.drill_id)
    infrai.report_suspected_compromise(request.compromised_key_id, confirmed_leak=True)
    logs = _log_records(infrai.search_logs())

    temporary = infrai.create_drill_key(
        project_id=request.project_id,
        idempotency_key=f"{drill_token}:create",
    )
    temporary_key_id = str(temporary["key_id"])
    try:
        infrai.rotate_drill_key(temporary_key_id, idempotency_key=f"{drill_token}:rotate")

        shipment_ids = sorted(
            {
                item.shipment_id
                for item in [*request.shipment_events, *request.proofs, *request.exceptions]
            }
        )
        return DrillResult(
            drill_id=request.drill_id,
            state="confirmed",
            temporary_key_id=temporary_key_id,
            blast_radius=BlastRadius(
                shipment_ids=shipment_ids,
                proof_object_keys=sorted(proof.object_key for proof in request.proofs),
                exception_count=len(request.exceptions),
                log_records_examined=len(logs),
            ),
        )
    finally:
        infrai.revoke_drill_key(temporary_key_id)
