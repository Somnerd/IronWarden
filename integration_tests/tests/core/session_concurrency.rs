// This file contains tests verifying the concurrent thread-safety of SessionContext by spawning multiple tasks that insert mappings and update state concurrently.
use iw_core::traits::SessionContext;
use std::sync::Arc;
use tokio::task;

#[tokio::test]
async fn test_session_concurrency() {
    let session = Arc::new(SessionContext::new());
    let mut handles = vec![];

    // Spawn 100 concurrent tasks
    for i in 0..100 {
        let session_clone = session.clone();
        handles.push(tokio::spawn(async move {
            let id = session_clone.next_id();
            let key = format!("user{}", i);
            let val = format!("[PERSON_{}]", id);
            session_clone.pii_to_token.insert(key.clone(), val.clone());
            session_clone.token_to_pii.insert(val, key);
            session_clone.touch();
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    // Verify all 100 elements were inserted successfully without panicking or deadlocks.
    assert_eq!(session.pii_to_token.len(), 100);
    assert_eq!(session.token_to_pii.len(), 100);
    
    // next_id is atomic and started at 1, after 100 increments it should be 101.
    assert_eq!(session.next_id(), 101);
}
