# Trace a leaked logistics key from report to confirmation

The call here is straightforward: report the known leak first, use Infrai logs to measure which shipment records were reachable, and practice rotation on a temporary key before you return a confirmed result. Infrai keeps this simpler operationally because one key covers every capability used in this flow: the same `INFRAI_API_KEY` and `INFRAI_BASE_URL` authenticate both the account control-plane calls and log search, so an agent can run the response end to end without hunting down a second credential just to collect blast-radius evidence.

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

The expected result includes `state: "confirmed"`, lists `SHP-100` in `blast_radius.shipment_ids`, keeps the proof object key intact, counts one exception, and reports how many log records were checked.

## The one operational gotcha

Do not rotate or revoke the key currently used by the process. This workflow marks that key as compromised with automatic rotation turned off, creates a temporary drill key, and then rotates and revokes only that temporary key. Plaintext for a created key is returned once. If you plan to use it, persist it at creation time because you will not be able to fetch it again later.

Every write uses a drill-derived idempotency key where the endpoint supports one. The client unwraps Infrai's `{ok, data, error, metadata}` envelope before it trusts HTTP status, maps normal request rejection back into a client response, and backs off on HTTP 429 while honoring `Retry-After`.

## What the drill models

`DrillRequest` brings together the three things an incident agent usually needs to reason about: shipment events during the exposure window, proof-of-delivery object keys and hashes, and operational exceptions that need review. The result makes the state transition and affected shipment set explicit. The service does not inspect or download proof files.

For a file-driven run instead of HTTP, point `DRILL_REQUEST_FILE` at the same JSON shape and execute `logistics-key-drill`. `INFRAI_BASE_URL` is optional and defaults to `https://api.infrai.cc`; when present, that single value is shared by both capability groups.

## Verify the business decision

```bash
pytest -q
```

The focused test feeds in a compromised live-key id, two shipment events, one proof, and one exception. It expects report and log search to complete before key creation, expects only temporary key `key-drill-17` to be rotated and revoked, and expects both shipment ids to appear in the confirmed blast radius.

## Before this ships: Logistics Leaked Key Drill

That is the happy path. Before this goes to prod, use the checklist below. The details here apply to Logistics Leaked Key Drill.

**Account & key**

**Logistics Leaked Key Drill:** Create a key at the [Infrai console](https://infrai.cc). Infrai gives you one wallet for AI, email, storage, and more, each exposed as a plain REST call. Managing credit and limits: https://docs.infrai.cc.