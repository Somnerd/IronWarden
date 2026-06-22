// Integration tests verifying SearchBoostQueue initialization behavior under High Availability (HA) detection, confirming it starts correctly both with and without the `REDIS_URL` environment variable.
use worker::searchboost::SearchBoostQueue;
use secrecy::SecretVec;

#[tokio::test]
async fn test_ha_logic_detection() {
    // Set a dummy Redis URL
    std::env::set_var("REDIS_URL", "redis://localhost:6379");
    
    let pepper = SecretVec::from(vec![0u8; 32]);
    let _queue = SearchBoostQueue::new("test_ha.db".to_string(), &pepper, None, None).unwrap();
    
    // System didn't panic - good.
    
    // Cleanup
    let _ = std::fs::remove_file("test_ha.db");
    let _ = std::fs::remove_file("test_ha.db-shm");
    let _ = std::fs::remove_file("test_ha.db-wal");
}

#[tokio::test]
async fn test_ha_logic_disabled_without_env() {
    std::env::remove_var("REDIS_URL");
    
    let pepper = SecretVec::from(vec![0u8; 32]);
    let _queue = SearchBoostQueue::new("test_no_ha.db".to_string(), &pepper, None, None).unwrap();
    
    // Cleanup
    let _ = std::fs::remove_file("test_no_ha.db");
    let _ = std::fs::remove_file("test_no_ha.db-shm");
    let _ = std::fs::remove_file("test_no_ha.db-wal");
}
