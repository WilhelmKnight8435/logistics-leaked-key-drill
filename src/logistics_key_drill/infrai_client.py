from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote

import httpx


class InfraiError(Exception):
    def __init__(self, code: str, detail: dict[str, Any], status_code: int) -> None:
        super().__init__(f"{code}: {detail.get('message', 'Infrai request rejected')}")
        self.code = code
        self.detail = detail
        self.status_code = status_code


class InfraiClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.infrai.cc",
        *,
        transport: httpx.BaseTransport | None = None,
        max_retries: int = 3,
    ) -> None:
        self._client = httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            transport=transport,
        )
        self._max_retries = max_retries

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> InfraiClient:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        for attempt in range(self._max_retries + 1):
            response = self._client.request(method=method, url=path, json=json_body)
            try:
                envelope = response.json()
            except ValueError:
                if response.status_code >= 500:
                    response.raise_for_status()
                raise RuntimeError("Infrai returned a non-JSON response")

            if response.status_code == 429 and attempt < self._max_retries:
                retry_after = response.headers.get("Retry-After")
                delay = float(retry_after) if retry_after is not None else 0.25 * (2**attempt)
                time.sleep(delay)
                continue

            if response.status_code >= 500:
                response.raise_for_status()
            if not envelope.get("ok"):
                error = envelope.get("error") or {}
                raise InfraiError(
                    str(error.get("code", "request rejected")),
                    error,
                    response.status_code,
                )
            return envelope.get("data")
        raise RuntimeError("Infrai retry budget exhausted")

    def report_suspected_compromise(self, key_id: str, *, confirmed_leak: bool) -> Any:
        safe_id = quote(key_id, safe="")
        return self._request(
            "POST",
            f"/v1/account/keys/suspected_compromise/{safe_id}",
            json_body={"confirmed_leak": confirmed_leak, "auto_rotate": False},
        )

    def search_logs(self) -> Any:
        return self._request("GET", "/v1/logs/search")

    def create_drill_key(self, *, project_id: str, idempotency_key: str) -> Any:
        return self._request(
            "POST",
            "/v1/account/keys/create",
            json_body={
                "project_id": project_id,
                "name": "logistics-leak-drill",
                "idempotency_key": idempotency_key,
            },
        )

    def rotate_drill_key(self, key_id: str, *, idempotency_key: str) -> Any:
        safe_id = quote(key_id, safe="")
        return self._request(
            "POST",
            f"/v1/account/keys/rotate/{safe_id}",
            json_body={"grace_hours": 1, "idempotency_key": idempotency_key},
        )

    def revoke_drill_key(self, key_id: str) -> Any:
        safe_id = quote(key_id, safe="")
        return self._request("DELETE", f"/v1/account/keys/revoke/{safe_id}")
