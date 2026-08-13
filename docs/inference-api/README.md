# Inference API

The Confidential Inference API provides OpenAI-compatible chat completions at
`https://api.confidential.ai`. The public gateway validates your API key and
forwards requests to the confidential inference service. It does not forward
your API key to the inference node.

## Quickstart

Set your API key and base URL:

```bash
export CONFIDENTIAL_API_KEY='replace-with-your-api-key'
export CONFIDENTIAL_API_BASE='https://api.confidential.ai'
```

List the models available to your key:

```bash
curl --fail --silent "$CONFIDENTIAL_API_BASE/v1/models" | jq .
```

Use a returned model ID to request a completion:

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

The completion response includes an `x-request-id` header. Save it if you need
to fetch a signed receipt for that request.

## Authentication

Inference requests require a Bearer API key:

```http
Authorization: Bearer <api-key>
```

The health, model, receipt, and attestation endpoints do not require a caller
API key. Do not put an API key in an attestation request or browser code.

## Next steps

- [API Spec](reference.md) — every endpoint, request field, response shape,
  error code, receipt, and attestation verification step.
- [Attestation](reference.md#attestation) — verify that the gateway and
  inference node evidence are fresh and correctly bound.
