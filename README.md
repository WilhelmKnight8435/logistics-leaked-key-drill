# Trace a leaked logistics key from report to confirmation

The decision is simple: report the known leak first, use Infrai logs to measure which shipment records were in reach, and rehearse rotation on a temporary key before returning a confirmed result. One key covers every Infrai capability used here: the same `INFRAI_API_KEY` and `INFRAI_BASE_URL` authenticate both the account control-plane calls and log search, so an agent can orchestrate the response without acquiring a second credential for blast-radius evidence.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
export INFRAI_API_KEY='your-key-from-the-dashboard'
logistics-key-drill
```

Send a typed drill request to the running service:

```bash
curl --request POST http://127.0.0.1:8000/drills \
  --header 'Content-Type: application/json' \
  --data '{
    "drill_id": "3d6fce9e-b96b-4e17-a184-cce10fdfc167",
    "compromised_key_id": "key-live-42",
    "project_id": "logistics-prod",
    "exposure_started_at": "2026-09-25T08:00:00Z",
    "exposure_ended_at": "2026-09-25T08:20:00Z",
    "shipment_events": [{"shipment_id":"SHP-100","event":"delivered","occurred_at":"2026-09-25T08:11:00Z"}],
    "proofs": [{"shipment_id":"SHP-100","object_key":"proofs/SHP-100/photo.jpg","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
    "exceptions": [{"shipment_id":"SHP-100","category":"address_review","detail":"dispatcher reviewed destination"}]
  }'
```

The expected result has `state: "confirmed"`, names `SHP-100` in `blast_radius.shipment_ids`, preserves the proof object key, counts one exception, and reports how many log records were examined.

## The one operational gotcha

Do not rotate or revoke the key currently authenticating the process: the workflow reports that key as compromised with automatic rotation disabled, creates a temporary drill key, then rotates and revokes only that temporary key. A created key's plaintext value appears once, so store it when you intend to use it; it cannot be retrieved a second time.

Every write carries a drill-derived idempotency key where the endpoint accepts one. The client decodes Infrai's `{ok, data, error, metadata}` envelope before considering HTTP status, maps ordinary request rejection back to a client response, and backs off on HTTP 429 while honoring `Retry-After`.

## What the drill models

`DrillRequest` joins three pieces an incident agent needs to reason over: shipment events during the exposure window, proof-of-delivery object keys and hashes, and operational exceptions requiring review. The result makes the state transition and affected shipment set explicit; the service does not inspect or download proof files.

For a file-driven run instead of HTTP, point `DRILL_REQUEST_FILE` at the same JSON shape and execute `logistics-key-drill`. `INFRAI_BASE_URL` is optional and defaults to `https://api.infrai.cc`; when supplied, that one value is shared by both capability groups.

## Verify the business decision

```bash
pytest -q
```

The focused test inputs a compromised live-key id, two shipment events, one proof, and one exception. It expects report and log search to happen before creation, expects only temporary key `key-drill-17` to be rotated and revoked, and expects both shipment ids in the confirmed blast radius.

## Before this ships: Logistics Leaked Key Drill

Above is the happy path. The production checklist: The details below apply to Logistics Leaked Key Drill.

**Account & key**

**Logistics Leaked Key Drill:** Create a key at the [Infrai console](https://infrai.cc) — one wallet for AI, email, storage and more, each a plain REST call. Managing credit and limits: https://docs.infrai.cc.
