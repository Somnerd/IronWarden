use crate::error::SovereignError;
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // The username/tenant_id
    pub exp: usize,
    #[serde(default)]
    pub roles: Vec<String>,
}

pub struct JwtVerifier;

impl JwtVerifier {
    pub fn verify(
        token: &str,
        public_key_pem: &[u8],
        audience: &str,
        issuer: &str,
    ) -> Result<Claims, SovereignError> {
        if crate::fips::FipsValidator::is_fips_enabled() {
            return Self::verify_fips(token, public_key_pem, audience, issuer);
        }

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[issuer]);

        let decoding_key = match DecodingKey::from_rsa_pem(public_key_pem) {
            Ok(k) => k,
            Err(_) => {
                return Err(SovereignError::InternalError(
                    "Invalid RSA Public Key Configuration".into(),
                ))
            }
        };

        match decode::<Claims>(token, &decoding_key, &validation) {
            Ok(token_data) => Ok(token_data.claims),
            Err(e) => {
                tracing::error!("JWT Validation Failure: {}", e);
                Err(SovereignError::UnauthorizedAccess(
                    "Invalid or Expired Token".into(),
                ))
            }
        }
    }

    fn verify_fips(
        token: &str,
        public_key_pem: &[u8],
        audience: &str,
        issuer: &str,
    ) -> Result<Claims, SovereignError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use openssl::{hash::MessageDigest, pkey::PKey, sign::Verifier};

        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(SovereignError::UnauthorizedAccess(
                "Invalid Token Format".into(),
            ));
        }

        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| SovereignError::UnauthorizedAccess("Invalid Header Format".into()))?;

        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|_| SovereignError::UnauthorizedAccess("Invalid Header JSON".into()))?;

        if header.get("alg").and_then(|v| v.as_str()) != Some("RS256") {
            tracing::error!("FIPS JWT Failure: Unsupported algorithm");
            return Err(SovereignError::UnauthorizedAccess(
                "Invalid or Expired Token".into(),
            ));
        }

        let pkey = PKey::public_key_from_pem(public_key_pem).map_err(|e| {
            tracing::error!("FIPS JWT Failure: Invalid PEM - {}", e);
            SovereignError::InternalError("Invalid RSA Public Key Configuration".into())
        })?;

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).map_err(|e| {
            tracing::error!("FIPS JWT Failure: Verifier init failed - {}", e);
            SovereignError::InternalError("Failed to initialize verifier".into())
        })?;

        let msg = format!("{}.{}", parts[0], parts[1]);
        verifier.update(msg.as_bytes()).map_err(|e| {
            tracing::error!("FIPS JWT Failure: Verifier update failed - {}", e);
            SovereignError::InternalError("Failed to update verifier".into())
        })?;

        let sig = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| SovereignError::UnauthorizedAccess("Invalid Signature Format".into()))?;

        if !verifier.verify(&sig).unwrap_or(false) {
            tracing::error!("FIPS JWT Validation Failure: Signature mismatch");
            return Err(SovereignError::UnauthorizedAccess(
                "Invalid or Expired Token".into(),
            ));
        }

        let claims_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| SovereignError::UnauthorizedAccess("Invalid Claims Format".into()))?;

        let claims_value: serde_json::Value = serde_json::from_slice(&claims_bytes)
            .map_err(|_| SovereignError::UnauthorizedAccess("Invalid Claims JSON".into()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        // Provide leeway for token expiration (60 seconds) similar to jsonwebtoken default
        if let Some(exp) = claims_value.get("exp").and_then(|v| v.as_u64()) {
            if (exp as usize) + 60 < now {
                tracing::error!("FIPS JWT Validation Failure: Token expired");
                return Err(SovereignError::UnauthorizedAccess(
                    "Invalid or Expired Token".into(),
                ));
            }
        } else {
            tracing::error!("FIPS JWT Validation Failure: Missing exp claim");
            return Err(SovereignError::UnauthorizedAccess(
                "Invalid or Expired Token".into(),
            ));
        }

        let aud_valid = match claims_value.get("aud") {
            Some(serde_json::Value::String(s)) => s == audience,
            Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(audience)),
            _ => false,
        };
        if !aud_valid {
            tracing::error!("FIPS JWT Validation Failure: Audience mismatch");
            return Err(SovereignError::UnauthorizedAccess(
                "Invalid or Expired Token".into(),
            ));
        }

        if claims_value.get("iss").and_then(|v| v.as_str()) != Some(issuer) {
            tracing::error!("FIPS JWT Validation Failure: Issuer mismatch");
            return Err(SovereignError::UnauthorizedAccess(
                "Invalid or Expired Token".into(),
            ));
        }

        let claims: Claims = serde_json::from_slice(&claims_bytes)
            .map_err(|_| SovereignError::UnauthorizedAccess("Invalid Claims Data".into()))?;

        Ok(claims)
    }
}

pub fn build_hkdf_info(info: &[u8], aad: &str) -> Vec<u8> {
    let aad_bytes = aad.as_bytes();

    // Pre-allocate the exact capacity to avoid reallocations
    // 4 bytes for info length + info payload + 4 bytes for aad length + aad payload
    let mut bound_context = Vec::with_capacity(8 + info.len() + aad_bytes.len());

    // 1. Push the length of `info` as a 32-bit Big-Endian integer
    bound_context.extend_from_slice(&(info.len() as u32).to_be_bytes());
    // 2. Push the `info` bytes
    bound_context.extend_from_slice(info);

    // 3. Push the length of `aad` as a 32-bit Big-Endian integer
    bound_context.extend_from_slice(&(aad_bytes.len() as u32).to_be_bytes());
    // 4. Push the `aad` bytes
    bound_context.extend_from_slice(aad_bytes);

    bound_context
}

/// Centralized utility for AAD-bound encryption using AES-256-GCM and HKDF.
/// This implementation ensures all sensitive data is bound to a specific user/tenant identity.
pub struct AadCipher;

impl AadCipher {
    /// Encrypts a payload with Associated Authenticated Data (AAD) and a secret pepper.
    pub fn encrypt(
        payload: &[u8],
        aad: &str,
        pepper: &[u8],
        info: &[u8],
    ) -> Result<Vec<u8>, SovereignError> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let bound_info = build_hkdf_info(info, aad);

        // Derive key using HKDF to ensure unique keys per context
        let hk = Hkdf::<Sha256>::new(None, pepper);
        let mut key_bytes = [0u8; 32];
        hk.expand(&bound_info, &mut key_bytes)
            .map_err(|_| SovereignError::InternalError("KDF expansion failed".into()))?;

        let key = Key::<Aes256Gcm>::from(key_bytes);
        let cipher = Aes256Gcm::new(&key);

        let aead_payload = aes_gcm::aead::Payload {
            msg: payload,
            aad: aad.as_bytes(),
        };

        let ciphertext = cipher
            .encrypt(&nonce, aead_payload)
            .map_err(|_| SovereignError::InternalError("Encryption failed".into()))?;

        // Securely erase key material from memory
        key_bytes.zeroize();

        let mut combined = nonce_bytes.to_vec();
        combined.extend(ciphertext);
        Ok(combined)
    }

    /// Decrypts a payload and verifies the Associated Authenticated Data (AAD).
    pub fn decrypt(
        combined: &[u8],
        aad: &str,
        pepper: &[u8],
        info: &[u8],
    ) -> Result<Vec<u8>, SovereignError> {
        if combined.len() < 12 {
            return Err(SovereignError::InternalError(
                "Corrupt ciphertext: too short".into(),
            ));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce_arr: [u8; 12] = nonce_bytes.try_into().unwrap();
        let nonce = Nonce::from(nonce_arr);

        let bound_info = build_hkdf_info(info, aad);

        // Derive key using HKDF (must match encryption parameters)
        let hk = Hkdf::<Sha256>::new(None, pepper);
        let mut key_bytes = [0u8; 32];
        hk.expand(&bound_info, &mut key_bytes)
            .map_err(|_| SovereignError::InternalError("KDF expansion failed".into()))?;

        let key = Key::<Aes256Gcm>::from(key_bytes);
        let cipher = Aes256Gcm::new(&key);

        let aead_payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: aad.as_bytes(),
        };

        let decrypted = cipher.decrypt(&nonce, aead_payload).map_err(|_| {
            SovereignError::InternalError(
                "Decryption failed (Integrity Mismatch or Incorrect AAD)".into(),
            )
        })?;

        // Securely erase key material from memory
        key_bytes.zeroize();
        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    const PEPPER: &[u8; 32] = b"01234567890123456789012345678901";
    const INFO: &[u8] = b"test_info";

    #[test]
    fn test_aad_cipher_roundtrip() {
        let payload = b"super secret message";
        let aad = "tenant_id_123";

        let encrypted = AadCipher::encrypt(payload, aad, PEPPER, INFO).unwrap();
        let decrypted = AadCipher::decrypt(&encrypted, aad, PEPPER, INFO).unwrap();

        assert_eq!(payload.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aad_cipher_wrong_key() {
        let payload = b"super secret message";
        let aad = "tenant_id_123";
        let wrong_pepper = b"11234567890123456789012345678901";

        let encrypted = AadCipher::encrypt(payload, aad, PEPPER, INFO).unwrap();
        let decrypted = AadCipher::decrypt(&encrypted, aad, wrong_pepper, INFO);

        assert!(decrypted.is_err(), "Should fail decryption with wrong key");
    }

    #[test]
    fn test_aad_cipher_wrong_aad_rejection() {
        let payload = b"super secret message";

        let encrypted = AadCipher::encrypt(payload, "userA", PEPPER, INFO).unwrap();
        let decrypted = AadCipher::decrypt(&encrypted, "userB", PEPPER, INFO);

        assert!(
            decrypted.is_err(),
            "V-19 Isolation Violation: Decrypted with wrong AAD"
        );
    }

    #[test]
    fn test_aad_cipher_tampered_ciphertext() {
        let payload = b"super secret message";
        let aad = "tenant_id_123";

        let mut encrypted = AadCipher::encrypt(payload, aad, PEPPER, INFO).unwrap();

        // Tamper with the last byte
        if let Some(last) = encrypted.last_mut() {
            *last ^= 1;
        }

        let decrypted = AadCipher::decrypt(&encrypted, aad, PEPPER, INFO);
        assert!(decrypted.is_err(), "Should reject tampered ciphertext");
    }

    #[test]
    fn test_aad_cipher_empty_payload() {
        let payload = b"";
        let aad = "tenant_id_123";

        let encrypted = AadCipher::encrypt(payload, aad, PEPPER, INFO).unwrap();
        let decrypted = AadCipher::decrypt(&encrypted, aad, PEPPER, INFO).unwrap();

        assert_eq!(payload.as_slice(), decrypted.as_slice());
    }

    // JWT tests
    const PRIVATE_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDWKHpjWw901PCx\nDi8HnsbyHY/+xBIpQQ7TpdJ5Kz2jjKoOUXGZbfmKneFXQH8BCCLTR9x7ufhwXI1B\nfn5Hi+7oD1xuAwz+u6gqeLyGbp8om5uoZhvzKnYeLNOC9qTXIzs24y8YWRDniluj\n/yKjyKttbfNzGg5UUlpSkoNmGIvQwzxN0wLLxCJRsJc5JV/AUGngK06p9T/hcu4V\naDW0bEene91pGixp90hDNVwKkDWz1PNU9KOwHuLIJxF+0EFSc3I+PNUqXG6P3In4\nC3JP5xd7ZrGDnNixfus1lXJxe8i/4+kO9Abuedb9BLHETAwHoN/yWy3TC1XLLLWV\n3CBqaumJAgMBAAECggEAFd4Aj+LtQ0TiUMnoeR2Neze+i3Pc1jPg6Nvj5QsfxPKT\ng1kYluM5BEjrs1DlcacG205ZT+mPhHWcLNBW4kUCaiqgtFEBGNpI07wL+qln/Kmq\n7WPZExgbrdLDmXnyyfmRzcsedMd/Z40On20T+JJVwsY5LLW/5HybjBaOw97aGUDu\nVXO8G2RLaDcrGIjydf8iXdKGldeVanFbAEbHuOcJceY3nW6EHawUctI7m22ZCtKu\nSgnA9SYiKamlNmEz223zeQh/K+8UNne3gERuxZ874c8t+Bi3cMInuPhpejl0bdCg\nYaJnL3OdMqnlWXm8mrHS05/XB2PyaFiw9ddtdcS5uwKBgQD04jwJSt3SwLzPRk+i\n5yZIVFoQ8T9O1+cQKQAXSwlN22//tpe44ba2C3FOkYrsU5bapT8VGnc8upQCDAk6\nyY6yeH5T5cFmylinNWFJAqHE2jV+wfbPgUmsRTYytIECq7OTixzLmLmY9vgaySBa\nARv6rGltDor38yxD7vo7sGz1gwKBgQDf4S9OXMB71Xv4xig5J9VjLN8A/u9kPjN/\npnibZF1/kQfpkekqbMveLZbbPKvGrCITiFlUTK9r9p2eBqUYtRyRV/BlKL71oVdB\nZiIivstEpucUhiKJiwrO8oJc/FpA+jRrfT5YBp07ki6jATLyuyVIBO3Rztm6AmXc\nS2EbdNaDAwKBgQCiVOZfcpWhg8qlzII2BuzFvcUGviWtaknt2IAK8N72EaUo6i2h\njV7FRsiRwMFK8A5sWmZ64tRwGW7L/JaRtdM2U9HKY9/U+AXUsfoPoAMEr3IO2R13\naMkhva+z5RwwXQnpoKox/Mfrsqu9dd5QS7P0dB5fAOj2fOi3D9ApiUZxaQKBgGY5\n56Tre0TQPVRh/xniE3C+m3FT9zGZqWA/PlEOKhdGvQstAf/KP+jKfljLQlBsZv7u\nQoPYpD0zFdODiz1V7Z58Phui2FdGfZYyMaIV5rEJWPipKvoNEDlgyJ/25qtG1ErE\nnIQLOR5raHor4Pyu8Z4KCiHERuzFjYdisAuedRjLAoGBAJTkcWpA/SKTkzjFNWfM\nYlzU1vsz9//0EHy//fDWeHqH6dWi1OOP/JnXtlDFHis6M/DvPeXAwjCFfXqnkbwZ\nPNa++c7N0aflBBOWUmo3+333Tqe/HXg/MKiAiIpRXJM2RAGUprL0P3XWXROMCwFQ\nOaWyPS+gFjrX3kXEYT60sBFa\n-----END PRIVATE KEY-----";

    const PUBLIC_KEY_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1ih6Y1sPdNTwsQ4vB57G\n8h2P/sQSKUEO06XSeSs9o4yqDlFxmW35ip3hV0B/AQgi00fce7n4cFyNQX5+R4vu\n6A9cbgMM/ruoKni8hm6fKJubqGYb8yp2HizTgvak1yM7NuMvGFkQ54pbo/8io8ir\nbW3zcxoOVFJaUpKDZhiL0MM8TdMCy8QiUbCXOSVfwFBp4CtOqfU/4XLuFWg1tGxH\np3vdaRosafdIQzVcCpA1s9TzVPSjsB7iyCcRftBBUnNyPjzVKlxuj9yJ+AtyT+cX\ne2axg5zYsX7rNZVycXvIv+PpDvQG7nnW/QSxxEwMB6Df8lst0wtVyyy1ldwgamrp\niQIDAQAB\n-----END PUBLIC KEY-----";

    #[derive(Debug, Serialize, Deserialize)]
    struct CustomClaims {
        sub: String,
        exp: usize,
        iss: String,
        aud: String,
        #[serde(default)]
        roles: Vec<String>,
    }

    fn generate_test_token(claims: &CustomClaims) -> String {
        let key = EncodingKey::from_rsa_pem(PRIVATE_KEY_PEM).unwrap();
        encode(&Header::new(Algorithm::RS256), claims, &key).unwrap()
    }

    #[test]
    fn test_jwt_valid_token() {
        let claims = CustomClaims {
            sub: "user_test".to_string(),
            exp: 9999999999, // far future
            iss: "test_issuer".to_string(),
            aud: "test_audience".to_string(),
            roles: vec![],
        };
        let token = generate_test_token(&claims);

        let verified = JwtVerifier::verify(&token, PUBLIC_KEY_PEM, "test_audience", "test_issuer");
        assert!(verified.is_ok());
        assert_eq!(verified.unwrap().sub, "user_test");
    }

    #[test]
    fn test_jwt_expired_token() {
        let claims = CustomClaims {
            sub: "user_test".to_string(),
            exp: 1000000000, // past
            iss: "test_issuer".to_string(),
            aud: "test_audience".to_string(),
            roles: vec![],
        };
        let token = generate_test_token(&claims);

        let verified = JwtVerifier::verify(&token, PUBLIC_KEY_PEM, "test_audience", "test_issuer");
        assert!(verified.is_err());
    }

    #[test]
    fn test_jwt_wrong_audience() {
        let claims = CustomClaims {
            sub: "user_test".to_string(),
            exp: 9999999999,
            iss: "test_issuer".to_string(),
            aud: "wrong_audience".to_string(),
            roles: vec![],
        };
        let token = generate_test_token(&claims);

        let verified = JwtVerifier::verify(&token, PUBLIC_KEY_PEM, "test_audience", "test_issuer");
        assert!(verified.is_err());
    }

    #[test]
    fn test_jwt_wrong_issuer() {
        let claims = CustomClaims {
            sub: "user_test".to_string(),
            exp: 9999999999,
            iss: "wrong_issuer".to_string(),
            aud: "test_audience".to_string(),
            roles: vec![],
        };
        let token = generate_test_token(&claims);

        let verified = JwtVerifier::verify(&token, PUBLIC_KEY_PEM, "test_audience", "test_issuer");
        assert!(verified.is_err());
    }

    #[test]
    fn test_jwt_invalid_pem() {
        let claims = CustomClaims {
            sub: "user_test".to_string(),
            exp: 9999999999,
            iss: "test_issuer".to_string(),
            aud: "test_audience".to_string(),
            roles: vec![],
        };
        let token = generate_test_token(&claims);

        let invalid_pem = b"-----BEGIN PUBLIC KEY-----\nabcd\n-----END PUBLIC KEY-----";
        let verified = JwtVerifier::verify(&token, invalid_pem, "test_audience", "test_issuer");
        assert!(verified.is_err());
    }

    #[test]
    fn test_jwt_tampered_signature() {
        let claims = CustomClaims {
            sub: "user_test".to_string(),
            exp: 9999999999,
            iss: "test_issuer".to_string(),
            aud: "test_audience".to_string(),
            roles: vec![],
        };
        let mut token = generate_test_token(&claims);

        // tamper signature
        token.pop();
        token.push('A');

        let verified = JwtVerifier::verify(&token, PUBLIC_KEY_PEM, "test_audience", "test_issuer");
        assert!(verified.is_err());
    }
}
