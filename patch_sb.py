import re

with open('worker/src/searchboost.rs', 'r') as f:
    content = f.read()

# 1. Update struct
content = content.replace(
"""    grounding_shield: Option<Arc<dyn iw_core::GroundingShield + Send + Sync>>,
    redis_client: Option<redis::Client>,
}""",
"""    grounding_shield: Option<Arc<dyn iw_core::GroundingShield + Send + Sync>>,
    redis_client: Option<redis::Client>,
    sender: crossbeam_channel::Sender<(String, String, Vec<u8>)>,
    receiver: crossbeam_channel::Receiver<(String, String, Vec<u8>)>,
    results: Arc<DashMap<String, Vec<u8>>>,
}"""
)

# 2. Update new()
content = content.replace(
"""        Ok(Self { 
            db_path, 
            pepper: Arc::new(SecretVec::new(pepper.expose_secret().to_vec())),
            conn: Arc::new(std::sync::Mutex::new(conn)),
            shield,
            grounding_shield,
            redis_client,
        })""",
"""        let (sender, receiver) = crossbeam_channel::unbounded();
        Ok(Self { 
            db_path, 
            pepper: Arc::new(SecretVec::new(pepper.expose_secret().to_vec())),
            conn: Arc::new(std::sync::Mutex::new(conn)),
            shield,
            grounding_shield,
            redis_client,
            sender,
            receiver,
            results: Arc::new(DashMap::new()),
        })"""
)

# 3. Update spawn_worker
old_worker = """    pub fn spawn_worker(&self, librarian: Arc<crate::librarian::LocalLibrarian>) {
        let queue = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                interval.tick().await;
                if let Err(e) = queue.process_next_job(librarian.clone()).await {
                    if !matches!(e, SovereignError::DatabaseBusy(_)) {
                        error!("SearchBoost Worker Error: {}", e);
                    }
                }
            }
        });
    }"""

new_worker = """    pub fn spawn_worker(&self, librarian: Arc<crate::librarian::LocalLibrarian>) {
        let queue = self.clone();
        
        // Startup recovery
        let conn_arc = self.conn.clone();
        let sender_clone = self.sender.clone();
        tokio::task::spawn_blocking(move || {
            if let Ok(conn) = conn_arc.lock() {
                if let Ok(mut stmt) = conn.prepare("SELECT id, username, query FROM search_jobs WHERE status = 'pending' ORDER BY created_at ASC") {
                    if let Ok(mut rows) = stmt.query([]) {
                        while let Ok(Some(row)) = rows.next() {
                            let id: String = row.get(0).unwrap_or_default();
                            let username: String = row.get(1).unwrap_or_default();
                            let encrypted_sanitized: Vec<u8> = row.get(2).unwrap_or_default();
                            let _ = sender_clone.send((id, username, encrypted_sanitized));
                        }
                    }
                }
            }
        });

        tokio::spawn(async move {
            loop {
                let job = match tokio::task::spawn_blocking({
                    let r = queue.receiver.clone();
                    move || r.recv()
                }).await {
                    Ok(Ok(j)) => j,
                    _ => continue,
                };
                
                let q2 = queue.clone();
                let lib2 = librarian.clone();
                
                let job_id = job.0.clone();
                let res = tokio::spawn(async move {
                    if let Err(e) = q2.process_job(job, lib2).await {
                        error!("SearchBoost Worker Error: {}", e);
                    }
                }).await;
                
                if res.is_err() {
                    error!("Worker thread panicked on job {}! Requeueing or marking failed.", job_id);
                    // Mark as failed in DB
                    let c = queue.conn.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        if let Ok(conn) = c.lock() {
                            let _ = conn.execute("UPDATE search_jobs SET status = 'failed' WHERE id = ?1", [&job_id]);
                        }
                    }).await;
                }
            }
        });
    }"""
content = content.replace(old_worker, new_worker)

# 4. Refactor process_next_job to process_job
old_process_start = """    pub async fn process_next_job(&self, librarian: Arc<crate::librarian::LocalLibrarian>) -> Result<(), SovereignError> {"""
new_process_start = """    pub async fn process_job(&self, job_data: (String, String, Vec<u8>), librarian: Arc<crate::librarian::LocalLibrarian>) -> Result<(), SovereignError> {"""
content = content.replace(old_process_start, new_process_start)

# We need to drop the Redis rpop and SQLite select logic in process_next_job
# from line 92 to line 131
pattern = re.compile(r'        // --- HA FIX \(WP 90\): Poll Redis first for distributed jobs ---.*?        let job = if let Some\(j\) = redis_job \{.*?        \};', re.DOTALL)
content = re.sub(pattern, '        let job = Some(job_data);', content)


# 5. Result update in process_job: update DashMap
pattern2 = re.compile(r'            let conn_arc = self\.conn\.clone\(\);\n            let id_clone = id\.clone\(\);\n            tokio::task::spawn_blocking\(move \|\| \{\n                let conn = conn_arc\.lock\(\)\.map_err\(\|\_\| SovereignError::InternalError\("Mutex poisoned"\.into\(\)\)\)\?;\n                conn\.execute\(\n                    "UPDATE search_jobs SET result = \?1, status = \'complete\' WHERE id = \?2",\n                    \(&encrypted_result, &id_clone\),\n                \)\.map_err\(\|e\| SovereignError::StorageError\(e\.to_string\(\)\)\)\?;\n                Ok::<\(\), SovereignError>\(\(\)\)\n            \}\)\.await\.map_err\(\|e\| SovereignError::InternalError\(format!\("Blocking task failed: \{\}", e\)\)\)\?\?;')

replacement2 = """            self.results.insert(id.clone(), encrypted_result.clone());

            let conn_arc = self.conn.clone();
            let id_clone = id.clone();
            let res_clone = encrypted_result.clone();
            tokio::task::spawn_blocking(move || {
                let conn = conn_arc.lock().map_err(|_| SovereignError::InternalError("Mutex poisoned".into()))?;
                conn.execute(
                    "UPDATE search_jobs SET result = ?1, status = 'complete' WHERE id = ?2",
                    (&res_clone, &id_clone),
                ).map_err(|e| SovereignError::StorageError(e.to_string()))?;
                Ok::<(), SovereignError>(())
            }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;"""

content = re.sub(pattern2, replacement2, content)

# 6. Enqueue: send to channel
pattern3 = re.compile(r'        info!\(job_id = %job_id, "Successfully enqueued encrypted SearchBoost job \(Sanitized\)"\);\n\n        Ok\(job_id\)')

replacement3 = """        let _ = self.sender.send((job_id.clone(), username.clone(), encrypted_sanitized.clone()));
        info!(job_id = %job_id, "Successfully enqueued encrypted SearchBoost job (Sanitized)");

        Ok(job_id)"""
content = re.sub(pattern3, replacement3, content)

# 7. Get Result: check DashMap
pattern4 = re.compile(r'        // --- HA FIX \(WP 90\): Check Redis first for result ---')

replacement4 = """        if let Some(res) = self.results.get(job_id) {
            let data = res.value().clone();
            let username = requester.to_string(); // In a real app we'd store username in DashMap too, but for now we skip admin check if it's in memory or assume it's valid if requested. Actually, let's just fetch it.
            // Wait, we need the username for decryption!
            // DashMap stores just the result bytes.
            // Let's modify DashMap to store (String, Vec<u8>)
            // But I didn't change DashMap definition above. Let's just fallback to redis/sqlite if we strictly need username.
            // Actually, we decrypt with requester username!
        }
        
        // --- HA FIX (WP 90): Check Redis first for result ---"""
# We will just rewrite `get_result` to check DashMap safely.

with open('worker/src/searchboost.rs', 'w') as f:
    f.write(content)
