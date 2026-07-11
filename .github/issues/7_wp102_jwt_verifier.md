# Title: [AUTH] Refactor JWT verification into reusable component (WP-102)

## Category: Security / Authentication

## Description
JWT token verification, signature checks, and identity claims extraction are currently hardcoded directly inside the API route handlers in the bridge server. This duplicates code and increases the risk of validation oversights during endpoint updates.

We need to extract and centralize the verification logic into a reusable `JwtVerifier` helper component.

## Technical Specifications
1.  **Implement JwtVerifier:** Create a reusable verifier struct in `core/src/auth.rs` using `jsonwebtoken` (or `jwt`):
    ```rust
    pub struct JwtVerifier {
        decoding_key: jsonwebtoken::DecodingKey,
        validation: jsonwebtoken::Validation,
    }
    ```
2.  **Expose Standard API:** Provide validation methods that verify signatures and return the authenticated `username` (bound to `sub` claim).
3.  **Bridge Integration:** Replace the ad-hoc validation blocks in the bridge server routes with calls to the new verifier component.
