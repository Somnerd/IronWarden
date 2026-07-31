# Title: [SECURITY] Wrap OpenAIGateway api_key in secrecy::SecretString

## Category: Security Hardening

## Description
Currently, the `OpenAIGateway` in `worker/src/router.rs` stores and passes around the upstream `api_key` as a raw plaintext `String` (see [router.rs:L21](file:///Users/nikolasalexandrakis/Documents/IronWarden/worker/src/router.rs#L21)).

Storing raw credentials in memory as plain `String` types is an anti-pattern. If the application panics, prints a debug trace of the gateway, or suffers a memory dump exploit, the raw API key could be leaked in plaintext logs or files.

To align with the project's Zero-Failure / Fail-Closed security posture, we must wrap all credentials in the `secrecy` crate's wrappers, which prevent accidental printing and zeroize the memory on drop.

## Remediation Plan
1. Update `OpenAIGateway` struct in `worker/src/router.rs`:
   ```rust
   use secrecy::SecretString;

   pub struct OpenAIGateway {
       client: Client,
       api_key: SecretString,
       base_url: String,
   }
   ```
2. Wrap it during initialization:
   ```rust
   impl OpenAIGateway {
       pub fn new(api_key: SecretString, base_url: String) -> Self { ... }
   }
   ```
3. Expose the secret safely when constructing the Authorization header:
   ```rust
   use secrecy::ExposeSecret;

   let response = self.client
       .post(&self.base_url)
       .header("Authorization", format!("Bearer {}", self.api_key.expose_secret()))
       .json(&payload)
       ...
   ```
4. Update `app/src/main.rs` to wrap the environment variable in `SecretString::new` when instantiating the gateway.
