# Confidential Inference

Private inference as an API. Pay per token.

Send requests to open-weight models running inside TEEs on our cloud. Your prompts, responses, and model interactions are never visible to us or our infrastructure. Every response includes an attestation proof.

OpenAI-compatible API. Drop-in replacement for existing inference providers. Switch your base URL and get hardware-enforced privacy with no other code changes.

| Model | Best for |
|---|---|
| GLM 5.1 | Reasoning, multilingual |
| Qwen 3.5 35B | General purpose |
| Qwen3.6 27B | General purpose |
| DeepSeek V4-Flash | General purpose, coding, long context |
| DeepSeek V4-Pro | Reasoning, coding, long context |

## Using the API

Point any OpenAI client at our base URL. Switch the base URL, keep the rest of your code. Every response carries an attestation you can verify.

```bash
curl https://api.confidential.ai/v1/chat/completions \
  -H "Authorization: Bearer $CONFIDENTIAL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-v4-pro",
    "messages": [{"role": "user", "content": "Explain remote attestation in one sentence."}]
  }'
```

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://api.confidential.ai/v1",
    api_key="$CONFIDENTIAL_API_KEY",
)

resp = client.chat.completions.create(
    model="deepseek-v4-pro",  # any model id from the table above
    messages=[{"role": "user", "content": "Explain remote attestation in one sentence."}],
)
print(resp.choices[0].message.content)
```

See [inference pricing](/pricing.md#confidential-inference) for per-token rates. Model requests: [hello@confidential.ai](mailto:hello@confidential.ai). Confidential inference vs non-confidential inference: 4% lower token throughput, negligible impact on Time to First Token (TTFT).
