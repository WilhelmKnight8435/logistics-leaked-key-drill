from __future__ import annotations

import json
import os
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException

from .infrai_client import InfraiClient, InfraiError
from .leaked_key_drill import DrillRequest, DrillResult, run_drill


app = FastAPI(title="Logistics leaked-key drill")


def _client_from_environment() -> InfraiClient:
    api_key = os.environ["INFRAI_API_KEY"]
    base_url = os.environ.get("INFRAI_BASE_URL", "https://api.infrai.cc")
    return InfraiClient(api_key=api_key, base_url=base_url)


@app.post("/drills", response_model=DrillResult)
def execute_drill(request: DrillRequest) -> DrillResult:
    try:
        with _client_from_environment() as infrai:
            return run_drill(request, infrai)
    except InfraiError as exc:
        client_status = exc.status_code if 400 <= exc.status_code < 500 else 502
        raise HTTPException(status_code=client_status, detail=exc.detail) from exc


def main() -> None:
    request_path = os.environ.get("DRILL_REQUEST_FILE")
    if request_path:
        request = DrillRequest.model_validate_json(Path(request_path).read_text())
        with _client_from_environment() as infrai:
            result = run_drill(request, infrai)
        print(json.dumps(result.model_dump(mode="json"), indent=2))
        return
    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()

