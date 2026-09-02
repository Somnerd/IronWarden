use std::collections::HashMap;
use worker::sse_proxy::SseRehydrator;

#[test]
fn test_streaming_rehydration_fuzz_arbitrary_chunk_splits() {
    let mut token_map = HashMap::new();
    token_map.insert("[PII_EMAIL_1]".to_string(), "ceo@enterprise.org".to_string());
    token_map.insert("[PII_SSN_1]".to_string(), "987-65-4321".to_string());
    token_map.insert("[PII_PHONE_1]".to_string(), "+1-555-867-5309".to_string());

    let original_stream_text = "The executive [PII_EMAIL_1] with SSN [PII_SSN_1] can be reached at [PII_PHONE_1] immediately.";
    let expected_output = "The executive ceo@enterprise.org with SSN 987-65-4321 can be reached at +1-555-867-5309 immediately.";

    // Test slicing into chunk sizes from 1 byte up to the whole string
    for chunk_size in 1..=original_stream_text.len() {
        let mut rehydrator = SseRehydrator::new(&token_map);
        let mut reconstructed = String::new();

        let bytes = original_stream_text.as_bytes();
        let mut offset = 0;

        while offset < bytes.len() {
            let end = (offset + chunk_size).min(bytes.len());
            // Ensure valid UTF-8 boundary slice
            let mut valid_end = end;
            while valid_end <= bytes.len() && std::str::from_utf8(&bytes[offset..valid_end]).is_err() {
                valid_end += 1;
            }
            let chunk_str = std::str::from_utf8(&bytes[offset..valid_end]).unwrap();
            let emitted = rehydrator.feed(chunk_str);
            reconstructed.push_str(&emitted);
            offset = valid_end;
        }

        reconstructed.push_str(&rehydrator.flush_all());
        assert_eq!(
            reconstructed, expected_output,
            "Rehydration failed for chunk_size={}",
            chunk_size
        );
    }
}

#[tokio::test]
async fn test_concurrent_multi_session_streaming_rehydration() {
    let mut handles = Vec::new();

    for user_idx in 0..50 {
        let handle = tokio::spawn(async move {
            let mut token_map = HashMap::new();
            let placeholder = format!("[PII_SECRET_{}]", user_idx);
            let secret = format!("User_{}_Classified_Token_Value", user_idx);
            token_map.insert(placeholder.clone(), secret.clone());

            let mut rehydrator = SseRehydrator::new(&token_map);
            let chunk1 = format!("Hello, your code is [PII_SECRET_");
            let chunk2 = format!("{}] - do not share.", user_idx);

            let out1 = rehydrator.feed(&chunk1);
            let out2 = rehydrator.feed(&chunk2);
            let flush = rehydrator.flush_all();

            let full = format!("{}{}{}", out1, out2, flush);
            let expected = format!("Hello, your code is {} - do not share.", secret);
            assert_eq!(full, expected);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("Task must not panic");
    }
}
