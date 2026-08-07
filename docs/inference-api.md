# Confidential Inference API

The Confidential Inference API provides OpenAI-compatible chat completions at
`https://api.confidential.ai`. The gateway validates the caller key at the
public boundary. It does not forward that key to the inference node.

All endpoints use HTTPS. Every response contains an `x-request-id` header.
Save this value when you need to fetch a completion receipt.

## Quickstart

Set your API key and read the available model list. Use a model ID from that
list in a completion request.

```bash
export CONFIDENTIAL_API_KEY='replace-with-your-api-key'
export CONFIDENTIAL_API_BASE='https://api.confidential.ai'

curl --fail --silent "$CONFIDENTIAL_API_BASE/v1/models" | jq .
```

```bash
curl --fail --silent "$CONFIDENTIAL_API_BASE/v1/chat/completions" \
  -H "Authorization: Bearer $CONFIDENTIAL_API_KEY" \
  -H 'Content-Type: application/json' \
  --data '{
    "model": "MODEL_ID_FROM_V1_MODELS",
    "messages": [{"role": "user", "content": "Reply with one word: ready."}],
    "stream": false
  }' | jq .
```

## Authentication

`POST /v1/chat/completions` requires this header:

```http
Authorization: Bearer <api-key>
```

The health, model, receipt, and attestation endpoints do not require a caller
API key. Do not put an API key in an attestation request or client-side code.

All JSON errors use this shape:

```json
{"error":{"code":"machine_readable_code"}}
```

## Endpoints

### `GET /health`

Returns gateway readiness. It is not attestation evidence.

```bash
curl --fail --silent "$CONFIDENTIAL_API_BASE/health" | jq .
```

Successful response:

```json
{"status":"ok"}
```

When the gateway cannot use its verified inference-node channel, it returns
`503 Service Unavailable`, `Retry-After: 1`, and:

```json
{"status":"unavailable"}
```

### `GET /v1/models`

Returns the public model catalog. This endpoint does not query an inference
worker.

```json
{
  "object": "list",
  "data": [
    {"id": "model-id", "object": "model"}
  ]
}
```

### `POST /v1/chat/completions`

Accepts an OpenAI-compatible chat-completions request. `model` is required and
must exactly match an ID from `GET /v1/models`. The gateway relays the remaining
valid request fields to the configured OpenAI-compatible inference service.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `model` | string | yes | An exact model ID from `GET /v1/models`. |
| `messages` | array | passed through | OpenAI-compatible messages. The gateway forwards this field unchanged. |
| `stream` | boolean | no | `false` or omitted returns JSON. `true` returns server-sent events. |

A non-streaming success is an OpenAI-compatible completion object with HTTP
`200 OK`.

```json
{
  "id": "chatcmpl-example",
  "object": "chat.completion",
  "model": "model-id",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "ready"},
    "finish_reason": "stop"
  }]
}
```

For `"stream": true`, the response content type is `text/event-stream`. The
stream contains OpenAI-compatible chunks and ends with `data: [DONE]`.

```text
data: {"object":"chat.completion.chunk","choices":[{"delta":{"content":"ready"}}]}

data: [DONE]
```

### `GET /v1/aci/receipts/{request_id}`

Returns a signed receipt for a recent completed request. Use the
`x-request-id` response header from `POST /v1/chat/completions` as
`{request_id}`.

```bash
curl --fail --silent \
  "$CONFIDENTIAL_API_BASE/v1/aci/receipts/$REQUEST_ID" | jq .
```

```json
{
  "draft": {
    "request_id": "request-id",
    "status": 200,
    "request_sha256": "sha256:...",
    "response_sha256": "sha256:...",
    "streaming": false
  },
  "created_at_unix_ms": 0,
  "algorithm": "ed25519",
  "signing_address": "base64url-ed25519-public-key",
  "signature": "base64url-ed25519-signature"
}
```

The receipt contains hashes and safe request metadata only. It does not contain
the prompt, completion, API key, or receipt private key. Receipts expire after
15 minutes. An unknown, expired, or unavailable receipt returns `404` with
`receipt_not_found`.

To verify a receipt, use the Ed25519 public key in `signing_address`. Verify
the signature over the UTF-8 JSON encoding of this exact object, with these
fields in this order:

```json
{
  "api_version": "aci/1",
  "purpose": "inference.receipt.v1",
  "request_id": "...",
  "request_sha256": "sha256:...",
  "response_sha256": "sha256:...",
  "status": 200,
  "streaming": false
}
```

Then verify that the same public key is present in the attestation response
that you trust.

### `GET /v1/aci/attestation?nonce={base64url}`

Returns the canonical attestation document. It does not require an API key.
`nonce` must be unpadded base64url and decode to exactly 32 random bytes.
Each nonce is single use.

```bash
NONCE="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"

curl --fail --silent \
  "$CONFIDENTIAL_API_BASE/v1/aci/attestation?nonce=$NONCE" | jq .
```

The response has this top-level shape. Evidence values are abbreviated here.
Use the exact returned values during verification.

```json
{
  "api_version": "aci/1",
  "workload_id": "gateway-workload-id",
  "workload_keyset_digest": "sha256:...",
  "attestation": {
    "vendor": "amd",
    "tee_type": "azure-vtpm-snp",
    "workload_keyset": {"receipt_signing_keys": [{"algo": "ed25519", "public_key": "..."}]},
    "report_data": "128-hex-character-value",
    "aci_statement_digest": "64-hex-character-value",
    "evidence": {
      "gateway": {"profile": "azure-vtpm-snp-commitment/v1", "...": "..."},
      "upstream_session_id": "as_...",
      "node": {"node_nonce": "...", "node_spki_sha256": "sha256:...", "c8s_evidence": {}}
    }
  }
}
```

HTTP `200` does not prove attestation. Verify all of these bindings:

1. Decode `attestation.report_data` as 64 bytes. Its final 32 bytes must equal
   your nonce. Its first 32 bytes must equal
   `SHA-256(receipt_signing_public_key || tls_certificate_fingerprint)`.
2. Read the live TLS certificate and compute the expected fingerprint. Use the
   receipt public key from `attestation.workload_keyset` for the first hash.
3. Recompute the Azure commitment:

   ```text
   SHA-256("confidential-gateway/aci-report-data/v1\0" || report_data)
   ```

   Compare it to the gateway commitment. Verify the Azure HCL report, vTPM
   attestation key, TPM quote, and AMD VCEK chain. The TPM quote qualifying
   data must equal this commitment.
4. Verify `attestation.evidence.node.c8s_evidence` with the expected TDX
   measurement and TCB policy. Its report data must bind the exact node TLS
   SPKI and your nonce. Compare the verified node SPKI hash with
   `node_spki_sha256`.
5. Fetch the linked session and verify its evidence digest and TLS channel
   binding as described below.

This gateway uses the `azure-vtpm-snp-commitment/v1` profile. Azure vTPM
evidence commits to the 64-byte value through the 32-byte commitment above. It
does not claim that a direct SNP guest report-data field contains the 64-byte
value.

Invalid nonce input returns `400 invalid_attestation_request`. Reusing a nonce
returns `409 attestation_nonce_replayed`. A full nonce guard returns `429
attestation_nonce_store_full`. When the gateway or node cannot provide fresh
evidence, the endpoint returns `503 attestation_unavailable`. Treat `503` as a
failed attestation result.

### `GET /v1/attestation/report?version=2&signing_algo=ecdsa&nonce={base64url}`

Returns a compatibility representation of the same gateway and node evidence.
The parameters must be exactly `version=2`, `signing_algo=ecdsa`, and a new
32-byte base64url nonce. Do not reuse a nonce from the canonical endpoint.

```bash
NONCE="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"

curl --fail --silent \
  "$CONFIDENTIAL_API_BASE/v1/attestation/report?version=2&signing_algo=ecdsa&nonce=$NONCE" \
  | jq .
```

It contains `signing_address`, a base64-encoded 64-byte `report_data`,
`gateway_attestation`, and `node_attestation`. Apply the same gateway and node
verification checks as for the canonical representation. This representation
does not include `api_version: "aci/1"` or `aci_statement_digest`.

### `GET /v1/aci/sessions/{session_id}`

Returns the short-lived node-attestation session linked by
`upstream_session_id` in an attestation response.

```json
{
  "api_version": "aci/1",
  "session_id": "as_...",
  "channel_binding": [{"type": "tls_spki_sha256", "spki_sha256": "sha256:..."}],
  "claims": {},
  "evidence": {
    "digest": "sha256:...",
    "data": "data:application/json;base64,..."
  }
}
```

Decode the evidence data URL and verify its SHA-256 digest before parsing it.
Compare the session TLS SPKI binding with the node binding in the attestation
response. The session is supporting evidence. It does not replace gateway or
node attestation verification. Unknown or expired sessions return `404
session_not_found`.

## Errors and retry rules

| HTTP | Code or body | Meaning | Client action |
| --- | --- | --- | --- |
| `400` | `invalid_request` | Completion JSON is invalid or `model` is missing. | Correct the request. |
| `400` | `invalid_attestation_request` | Attestation parameters are invalid. | Generate a valid new nonce. |
| `401` | `invalid_api_key` | The caller key is missing or invalid. | Obtain a valid key. Do not retry unchanged. |
| `404` | `model_not_found` | The model is not in the catalog. | Use `GET /v1/models`. |
| `404` | `receipt_not_found` | The receipt is unavailable or expired. | Use the correct recent request ID. |
| `404` | `session_not_found` | The attestation session is unavailable or expired. | Request new attestation with a new nonce. |
| `409` | `attestation_nonce_replayed` | The attestation nonce was already used. | Generate a new nonce. |
| `429` | `upstream_unavailable` | The verified node path is temporarily unavailable. | Honor `Retry-After` when present and retry safely. |
| `429` | `attestation_nonce_store_full` | The nonce guard is full. | Back off and retry with a new nonce. |
| `503` | `attestation_unavailable` | Fresh gateway or node evidence is unavailable. | Fail closed. Do not accept cached or partial evidence. |
| `503` | `{"status":"unavailable"}` | The gateway is not ready. | Honor `Retry-After` and retry. |
