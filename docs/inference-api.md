# Confidential Inference API

The Confidential Inference API is an OpenAI-compatible API for confidential
inference. The current integration staging endpoint is
`https://staging.api.confidential.ai`.

The gateway checks API keys at the public boundary. It does not send the key to
the inference service. Every public response includes an `x-request-id` header.
Use this ID when you contact support about a request. It is not a receipt ID.

## Quickstart

Set an API key and read the model list. The staging model is
`staging-mock`. Use the model ID returned by `/v1/models` in your request.

```bash
export CONFIDENTIAL_API_KEY='replace-with-your-api-key'
export CONFIDENTIAL_API_BASE='https://staging.api.confidential.ai'

curl --fail --silent "$CONFIDENTIAL_API_BASE/v1/models" \
  -H "Authorization: Bearer $CONFIDENTIAL_API_KEY" | jq .
```

```bash
curl --fail --silent "$CONFIDENTIAL_API_BASE/v1/chat/completions" \
  -H "Authorization: Bearer $CONFIDENTIAL_API_KEY" \
  -H 'Content-Type: application/json' \
  --data '{
    "model": "staging-mock",
    "messages": [{"role": "user", "content": "Reply with one word: ready."}],
    "stream": false
  }' | jq .
```

## Authentication

Every path under `/v1/` requires this header:

```http
Authorization: Bearer <api-key>
```

The public `/health` and `/attestation` paths do not require an API key. Do not
put an API key in an attestation request or in client-side code that users can
inspect.

JSON errors use this shape:

```json
{
  "error": {
    "code": "machine_readable_code",
    "message": "Human-readable message"
  }
}
```

## Endpoints

### `GET /health`

Returns the gateway process health. This endpoint does not prove that the
inference service is available and does not return attestation evidence.

```bash
curl --fail --silent "$CONFIDENTIAL_API_BASE/health" | jq .
```

Successful response:

```json
{"status":"ok"}
```

### `GET /attestation?nonce={base64url}`

Returns fresh launch or admission evidence for the staging gateway and its
inference workloads. This endpoint does not require an API key.

The `nonce` must be unpadded URL-safe base64. The decoded value must contain
exactly 32 random bytes. A nonce is single use. Generate a new nonce for every
request:

```bash
NONCE="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"

curl --fail --silent \
  "$CONFIDENTIAL_API_BASE/attestation?nonce=$NONCE" | jq .
```

The gateway sends the nonce to all four staging workload attestation sidecars:
the gateway, router, and two mock-inference workers. A successful response has
this shape. Evidence fields are abbreviated here.

```json
{
  "schemaVersion": 1,
  "scope": "launch-or-admission-only",
  "nonce": "43-character-base64url-value",
  "operationalStatus": "not-verified",
  "receipts": [
    {"target": "gateway", "workload": "gateway", "receipt": {}},
    {"target": "sglang-router", "workload": "sglang-router", "receipt": {}},
    {"target": "mock-inference-0", "workload": "mock-inference-worker", "receipt": {}},
    {"target": "mock-inference-1", "workload": "mock-inference-worker", "receipt": {}}
  ]
}
```

Each receipt is a standard `c8s/attest-pq/v1` receipt. Verify every receipt
with an independent c8s verifier. The response proves launch or admission
facts only. It does not prove current workload health, request routing, mount
contents, environment values, GPU state, or model use.

The endpoint also accepts the nonce in the `X-Attestation-Nonce` header. Do not
send both the query parameter and the header.

### `GET /v1/models`

Returns the model catalog. This path requires an API key and does not query an
inference worker.

```bash
curl --fail --silent "$CONFIDENTIAL_API_BASE/v1/models" \
  -H "Authorization: Bearer $CONFIDENTIAL_API_KEY" | jq .
```

Staging returns the deterministic mock model:

```json
{
  "object": "list",
  "data": [
    {"id": "staging-mock", "object": "model", "owned_by": "confidential.ai"}
  ]
}
```

### `POST /v1/chat/completions`

Accepts an OpenAI-compatible chat-completions request. This path requires an
API key. The `model` value must exactly match an ID from `/v1/models`. The
`messages` array is required by the staging mock.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `model` | string | yes | An exact model ID from `/v1/models`. |
| `messages` | array | yes | OpenAI-compatible chat messages. |
| `stream` | boolean | no | `false` or omitted returns JSON. `true` returns server-sent events. |
| Other OpenAI fields | varies | no | The gateway passes valid JSON fields to the inference service. |

The staging mock returns this deterministic text in a non-streaming response:
`staging mock response`.

```json
{
  "id": "request-id",
  "object": "chat.completion",
  "created": 0,
  "model": "staging-mock",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "staging mock response"},
    "finish_reason": "stop"
  }],
  "usage": {"prompt_tokens": 1, "completion_tokens": 3, "total_tokens": 4}
}
```

For `"stream": true`, the response content type is `text/event-stream`. It
contains OpenAI-compatible chunks and ends with `data: [DONE]`.

### `POST /v1/completions`

Accepts an OpenAI-compatible legacy text-completions request. This path
requires an API key. The `model` value must exactly match an ID from
`/v1/models`, and the `prompt` value must be a string or an array.

```json
{
  "model": "staging-mock",
  "prompt": "Reply with one word: ready.",
  "stream": false
}
```

The staging mock returns `staging mock response` in the `choices[0].text`
field. With `"stream": true`, it returns server-sent events and ends with
`data: [DONE]`.

## Staging behavior

Staging uses a deterministic mock inference service. Its model ID is
`staging-mock`, and successful chat and text completions return the fixed text
`staging mock response`. This service is for integration checks. It is not a
production model and its response is not a quality or performance benchmark.

The mock can produce controlled upstream error, timeout, and malformed-response
cases for internal integration tests. Do not depend on those test modes in a
client integration.

## API keys and the admin dashboard

API keys are created for an environment by the Confidential admin dashboard at
`https://admin.api.confidential.ai`. The dashboard requires Google Workspace
authentication for an approved `@confidential.ai` account.

Select `staging` to create a staging key. The plaintext key is shown only in
the successful create response. Copy it before you dismiss the message. The
dashboard stores and shows key metadata after that, but it does not show the
plaintext key again. Delete or revoke a key when you no longer need it.

The browser uses the dashboard session. It does not receive gateway signing
credentials and it does not call the gateway admin API directly.

## Errors and retry rules

| HTTP | Code | Meaning | Client action |
| --- | --- | --- | --- |
| `400` | `invalid_json` | The request body is not valid JSON. | Correct the JSON. |
| `400` | `model_required` | The request does not contain a model. | Add the model ID from `/v1/models`. |
| `400` | `invalid_nonce` or `nonce_required` | The attestation nonce is missing or not exactly 32 bytes after decoding. | Generate a new 32-byte unpadded base64url nonce. |
| `400` | `ambiguous_nonce` | Both nonce sources were sent, or a source was sent more than once. | Send one nonce source only. |
| `401` | `invalid_api_key` | The `/v1/` request has no valid bearer key. | Obtain a valid key. Do not retry unchanged. |
| `404` | `model_not_found` | The model is not in the catalog. | Call `/v1/models` and use its model ID. |
| `409` | `nonce_rejected` | The attestation nonce was already used or the nonce guard is full. | Generate a new nonce and retry later if needed. |
| `413` | `request_too_large` | The request body is larger than the gateway limit. | Reduce the request size. |
| `502` | `upstream_unavailable` or `attestation_invalid` | The verified upstream or attestation response failed. | Fail closed and retry only when safe. |
| `503` | `attestation_unavailable` | Fresh attestation evidence is not available. | Do not accept cached or partial evidence. |

The gateway can also return an upstream status and error body from the
inference service. Honor `Retry-After` when it is present. Never retry a
request with a revoked key.
