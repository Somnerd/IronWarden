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
