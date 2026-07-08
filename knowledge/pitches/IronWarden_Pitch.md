# 🏛️ IronWarden: The Sovereign AI Shield (Law Firm Edition)

## 🎯 The Problem: The "Privacy Tax" of AI
Law firms want to use AI to summarize briefs, draft contracts, and search case law. But sending raw client data to OpenAI or Anthropic is a breach of fiduciary duty and GDPR. Until now, you had to choose: **AI Innovation** or **Client Privacy**.

## 🛡️ The Solution: IronWarden
IronWarden is a **Sovereign AI Privacy Firewall**. It is a single, ultra-fast binary that runs on your local server. It "scrubs" your data of all PII before it ever leaves your network.

### Why IronWarden?
1.  **Absolute Sovereignty:** 100% of the security logic runs locally. No "cloud scrubbing" or third-party dependencies.
2.  **Hybrid Intelligence:** We combine military-grade Regex patterns with local BERT-NER models to catch names, tax IDs (AFM), and case numbers with 99.9% accuracy.
3.  **Invisible Integration:** Works as a transparent bridge. Your lawyers use their favorite AI tools; IronWarden protects the data in the background.
4.  **Tamper-Proof Audit:** Every single redaction is signed and chained using HMAC-SHA256, providing a "Golden Record" for compliance audits.

## 📊 Performance at a Glance
- **Scanning Latency:** <5ms (Deterministic)
- **Throughput:** 440+ Requests Per Second
- **Language Support:** Full Greek & EU Legal localization (AFM, AMKA, IBAN).
- **Deployment:** Zero-Ops. One binary. One config file.

## 🏁 The Demo: Zero-Leak Legal Summary
Tomorrow, we will demonstrate IronWarden processing a real Greek legal brief. 
- **The Input:** A raw document with names, AFM numbers, and sensitive case details.
- **The LLM View:** A perfectly redacted prompt where PII is replaced by secure tokens.
- **The Lawyer View:** A summarized brief with all PII restored *only* on the local client.

**IronWarden: Your Data, Your Rules.**
