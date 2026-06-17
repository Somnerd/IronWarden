use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::RngCore;
use zeroize::Zeroize;
use crate::error::SovereignError;

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
        let nonce = Nonce::from_slice(&nonce_bytes);

        let bound_info = build_hkdf_info(info, aad);

        // Derive key using HKDF to ensure unique keys per context
        let hk = Hkdf::<Sha256>::new(None, pepper);
        let mut key_bytes = [0u8; 32];
        hk.expand(&bound_info, &mut key_bytes)
            .map_err(|_| SovereignError::InternalError("KDF expansion failed".into()))?;
        
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let aead_payload = aes_gcm::aead::Payload {
            msg: payload,
            aad: aad.as_bytes(),
        };

        let ciphertext = cipher.encrypt(nonce, aead_payload)
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
            return Err(SovereignError::InternalError("Corrupt ciphertext: too short".into()));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let bound_info = build_hkdf_info(info, aad);

        // Derive key using HKDF (must match encryption parameters)
        let hk = Hkdf::<Sha256>::new(None, pepper);
        let mut key_bytes = [0u8; 32];
        hk.expand(&bound_info, &mut key_bytes)
            .map_err(|_| SovereignError::InternalError("KDF expansion failed".into()))?;
        
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let aead_payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: aad.as_bytes(),
        };

        let decrypted = cipher.decrypt(nonce, aead_payload)
            .map_err(|_| SovereignError::InternalError("Decryption failed (Integrity Mismatch or Incorrect AAD)".into()))?;

        // Securely erase key material from memory
        key_bytes.zeroize();
        Ok(decrypted)
    }
}
