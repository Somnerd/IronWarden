# ⚡ Quickstart Guide — IronWarden AI Gateway

Welcome to IronWarden! Get up and running in seconds with either our **zero-dependency interactive demo** or the **production Docker Compose stack**.

---

## ⚡ 10-Second Instant Demo (Zero Dependencies)

Try IronWarden immediately without installing Docker, Tesseract OCR, or downloading ML weights:

```bash
git clone https://github.com/Somnerd/IronWarden.git
cd IronWarden
./scripts/demo.sh
```

**What the demo does:**
1. Generates ephemeral in-memory RSA keypairs for zero-trust JWT authentication.
2. Boots IronWarden in **Heuristic-Only mode** on `http://localhost:8080`.
3. Intercepts a test payload with simulated SSNs, emails, IBANs, and phone numbers.
4. Performs real-time dual-track PII redaction and SHA-256 HMAC audit chaining before your eyes.

---

## 🚀 1-Click Deployment (Docker Compose)

### Prerequisites
* [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed on your machine.

### Step 1: Clone & Start the Gateway
```bash
git clone https://github.com/Somnerd/IronWarden.git
cd IronWarden

# Start IronWarden and the Redis session store
docker-compose up -d
```

Verify that the gateway is running:
```bash
curl http://localhost:8080/health
# Response: {"status":"healthy","version":"1.0.0-rc.1","mode":"sovereign"}
```

---

## 🛡️ Routing Requests Through the Gateway

IronWarden acts as a zero-trust security proxy in front of OpenAI, Anthropic, or local LLM providers.

### Option A: Using `curl`

Send an OpenAI-compatible request through the proxy:

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4o",
    "messages": [
      {
        "role": "user",
        "content": "My name is John Doe, my SSN is 000-12-3456, and my email is john@example.com."
      }
    ]
  }'
```

* **What happens behind the scenes**:
  1. IronWarden's dual-track PII engine scrubs `John Doe`, `000-12-3456`, and `john@example.com` into zero-leak token placeholders.
  2. The sanitized prompt is forwarded to OpenAI.
  3. The response is re-hydrated with original tokens before returning to your client.
  4. An immutable SHA-256 HMAC audit entry is recorded in the local audit ledger.

---

### Option B: Using Python (`openai` SDK)

Drop IronWarden straight into your existing OpenAI Python code by overriding `base_url`:

```python
import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY", "your-api-key"),
    base_url="http://localhost:8080/v1" # Route through IronWarden Gateway
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "user", "content": "Contact John at +30 6912345678 or AMKA 01019012345."}
    ]
)

print(response.choices[0].message.content)
```

---

### Option C: Anthropic Claude (`/v1/messages`)

IronWarden natively supports Anthropic's Messages API protocol:

```bash
curl -X POST http://localhost:8080/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 1024,
    "messages": [
      {"role": "user", "content": "Analyze user profile for AFM 123456789."}
    ]
  }'
```

---

## ⚙️ Customizing Security Policies

IronWarden's rules engine is configured via YAML files in `./config/rules/`.

To test strict mode or modify custom PII redaction rules:

1. Open `config/rules/strict_mode.yaml`:
   ```yaml
   strict_mode: true
   fail_closed: true
   pii_categories:
     - IndividualName
     - IdentificationNumber
     - ContactInfo
     - CreditCard
   actions:
     IdentificationNumber: Block # Hard block prompt injection & ID leaks
     IndividualName: Redact
   ```
2. Save the file. IronWarden hot-reloads configuration changes instantly without restarting!

---

## 🔗 Connecting to Existing Infrastructure

If you already run Redis (e.g., inside a Grounding deployment), you can point IronWarden to your existing Redis container:

```bash
# In your .env file or shell environment:
export REDIS_URL=redis://:your_password@localhost:6379
docker-compose up -d
```

---

## 📖 Next Steps

* Read [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.
* Check out [CONTRIBUTING.md](CONTRIBUTING.md) to set up a local development environment in Rust.
