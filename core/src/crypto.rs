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

    /// Generates an ephemeral 2048-bit RSA keypair and a pre-signed demo JWT token
    /// for zero-config local testing and quickstart demos.
    pub fn generate_ephemeral_demo_keypair(
        audience: &str,
        issuer: &str,
    ) -> Result<(Vec<u8>, String), SovereignError> {
        let rsa = openssl::rsa::Rsa::generate(2048).map_err(|e| {
            SovereignError::InternalError(format!(
                "Failed to generate ephemeral RSA keypair: {}",
                e
            ))
        })?;
        let priv_pem = rsa.private_key_to_pem().map_err(|e| {
            SovereignError::InternalError(format!("Failed to serialize RSA private key: {}", e))
        })?;
        let pub_pem = rsa.public_key_to_pem().map_err(|e| {
            SovereignError::InternalError(format!("Failed to serialize RSA public key: {}", e))
        })?;

        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(&priv_pem).map_err(|e| {
            SovereignError::InternalError(format!("Failed to load encoding key: {}", e))
        })?;

        #[derive(Serialize)]
        struct DemoClaims<'a> {
            sub: &'a str,
            aud: &'a str,
            iss: &'a str,
            exp: usize,
            roles: Vec<&'a str>,
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = DemoClaims {
            sub: "demo_admin",
            aud: audience,
            iss: issuer,
            exp: now + 365 * 24 * 3600, // Valid for 1 year in demo mode
            roles: vec!["admin", "privileged_search"],
        };

        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = None;

        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).map_err(|e| {
            SovereignError::InternalError(format!("Failed to generate demo JWT token: {}", e))
        })?;

        Ok((pub_pem, token))
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
