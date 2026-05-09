use clap::{Parser, Subcommand};
use rusqlite::Connection;
use serde_json::Value;
use std::collections::HashMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use hkdf::Hkdf;
use secrecy::{SecretString, ExposeSecret};
use iw_core::{Redaction, KDF_SALT_INTEGRITY, KDF_SALT_GENESIS};

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser)]
#[command(name = "iw-cli")]
#[command(about = "IronWarden Compliance & Reporting CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generates a Risk Mitigation Report from the audit database
    Report {
        /// Path to the SQLite audit database
        #[arg(short, long, default_value = "audit.db")]
        db: String,
    },
    /// Verifies the cryptographic integrity of the audit ledger
    Verify {
        /// Path to the SQLite audit database
        #[arg(short, long, default_value = "audit.db")]
        db: String,
        /// The WARDEN_PEPPER used for HMAC generation
        #[arg(short, long)]
        pepper: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Report { db } => {
            if let Err(e) = generate_report(db) {
                eprintln!("Error generating report: {}", e);
            }
        }
        Commands::Verify { db, pepper } => {
            let secret_pepper = SecretString::from(pepper.clone());
            if let Err(e) = verify_integrity(db, &secret_pepper) {
                eprintln!("Error verifying integrity: {}", e);
            }
        }
    }
}

fn generate_report(db_path: &str) -> rusqlite::Result<()> {
    let conn = Connection::open(db_path)?;
    
    let mut total_requests = 0;
    let mut total_blocked = 0;
    let mut rule_counts: HashMap<String, u32> = HashMap::new();
    let mut ai_redactions = 0;

    let mut stmt = conn.prepare("SELECT is_blocked, redactions_json FROM audit_reports")?;
    let report_iter = stmt.query_map([], |row| {
        let is_blocked: bool = row.get(0)?;
        let redactions_json: String = row.get(1)?;
        Ok((is_blocked, redactions_json))
    })?;

    for report_res in report_iter {
        let (is_blocked, redactions_json) = report_res?;
        total_requests += 1;
        if is_blocked {
            total_blocked += 1;
        }

        if let Ok(redactions) = serde_json::from_str::<Vec<Value>>(&redactions_json) {
            for redaction in redactions {
                if let Some(rule_id) = redaction.get("rule_id").and_then(|v| v.as_str()) {
                    if rule_id == "ai_hybrid_validation" {
                        ai_redactions += 1;
                    }
                    *rule_counts.entry(rule_id.to_string()).or_insert(0) += 1;
                }
            }
        }
    }

    println!("\n=============================================");
    println!("🛡️  IRONWARDEN RISK MITIGATION REPORT 🛡️");
    println!("=============================================\n");
    println!("📊 OVERALL METRICS:");
    println!("  Total Prompts Scanned : {}", total_requests);
    println!("  Total Prompts Blocked : {}", total_blocked);
    println!("  Total AI Redactions   : {}", ai_redactions);
    
    println!("\n🔍 RULE TRIGGER FREQUENCY:");
    let mut sorted_rules: Vec<_> = rule_counts.into_iter().collect();
    sorted_rules.sort_by(|a, b| b.1.cmp(&a.1));
    for (rule, count) in sorted_rules {
        println!("  - {}: {} hits", rule, count);
    }
    println!("\n=============================================\n");

    Ok(())
}

fn verify_integrity(db_path: &str, pepper: &SecretString) -> rusqlite::Result<()> {
    let conn = Connection::open(db_path)?;
    
    let hk = Hkdf::<Sha256>::new(None, pepper.expose_secret().as_bytes());
    let mut hmac_key_bytes = [0u8; 32];
    hk.expand(KDF_SALT_INTEGRITY, &mut hmac_key_bytes).map_err(|_e| {
        rusqlite::Error::InvalidQuery
    })?;

    let mut genesis_hash = [0u8; 32];
    hk.expand(KDF_SALT_GENESIS, &mut genesis_hash).map_err(|_e| {
        rusqlite::Error::InvalidQuery
    })?;

    // We verify by joining audit_reports and ephemeral_raw_logs where they match by ID
    // Note: Due to 30-day log purging, older records cannot be cryptographically verified.
    let mut stmt = conn.prepare(
        "SELECT a.id, a.timestamp, a.is_blocked, a.redactions_json, a.integrity_hash, e.nonce, e.encrypted_data \
         FROM audit_reports a \
         LEFT JOIN ephemeral_raw_logs e ON a.id = e.id \
         ORDER BY a.id ASC"
    )?;

    let iter = stmt.query_map([], |row| {
        let id: i64 = row.get(0)?;
        let timestamp: String = row.get(1)?;
        let is_blocked: bool = row.get(2)?;
        let redactions_json: String = row.get(3)?;
        let integrity_hash_hex: String = row.get(4)?;
        
        // ephemeral log fields might be missing due to 30-day purge
        let nonce: Option<Vec<u8>> = row.get(5).ok().flatten();
        let ciphertext: Option<Vec<u8>> = row.get(6).ok().flatten();
        
        Ok((id, timestamp, is_blocked, redactions_json, integrity_hash_hex, nonce, ciphertext))
    })?;

    let mut last_hash: Vec<u8> = genesis_hash.to_vec();
    let mut verified_count = 0;
    let mut archived_count = 0;
    let mut tampered_count = 0;

    println!("\n=============================================");
    println!("⛓️  IRONWARDEN TAMPER-CHECK INTEGRITY TOOL ⛓️");
    println!("=============================================\n");

    for row_res in iter {
        let (id, timestamp, is_blocked, redactions_json, integrity_hash_hex, nonce_opt, ciphertext_opt) = row_res?;
        let stored_hash = hex::decode(&integrity_hash_hex).unwrap_or_default();

        let redactions_vec: Vec<Redaction> = serde_json::from_str(&redactions_json).unwrap_or_default();
        let redactions_bin = bincode::serialize(&redactions_vec).unwrap_or_default();

        let mut mac = HmacSha256::new_from_slice(&hmac_key_bytes).expect("HMAC can take key of any size");
        mac.update(&last_hash);
        mac.update(timestamp.as_bytes());
        mac.update(&[is_blocked as u8]);
        mac.update(&redactions_bin);
        
        let calculated_hash = mac.finalize().into_bytes().to_vec();
        
        if calculated_hash == stored_hash {
            if nonce_opt.is_some() && ciphertext_opt.is_some() {
                verified_count += 1;
            } else {
                archived_count += 1;
            }
        } else {
            println!("❌ TAMPER DETECTED at Log ID {}!", id);
            println!("   Expected Hash: {}", hex::encode(&calculated_hash));
            println!("   Stored Hash  : {}", integrity_hash_hex);
            tampered_count += 1;
        }

        // Always update last_hash so the chain continues
        last_hash = stored_hash;
    }

    println!("✅ Verified Intact Logs: {}", verified_count);
    println!("📦 Verified Archived Logs: {} (Ephemeral data purged)", archived_count);
    
    if tampered_count == 0 {
        println!("\n✨ STATUS: CHAIN INTACT ✨");
        println!("=============================================\n");
    } else {
        println!("\n🚨 STATUS: CHAIN CORRUPTED ({} records tampered) 🚨", tampered_count);
        println!("=============================================\n");
        std::process::exit(1);
    }

    Ok(())
}
