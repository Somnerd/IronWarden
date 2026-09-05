# IronWarden Python SDK

The official, lightweight Python helper client for **IronWarden** — the high-performance Sovereign AI Reverse Proxy and Privacy Firewall.

## Installation
```bash
pip install ironwarden
```

## Quickstart

```python
from ironwarden import IronWarden

# Automatically points to http://localhost:14141/v1
client = IronWarden(
    api_key="your-api-key",
    gateway_url="http://localhost:14141/v1" # optional, defaults to localhost:14141/v1
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "user", "content": "Patient John Doe (SSN: 123-45-6789) visited today."}
    ],
    stream=True
)

for chunk in response:
    if chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
```
