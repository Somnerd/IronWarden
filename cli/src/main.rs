use clap::{Parser, Subcommand};
use rusqlite::Connection;
use serde_json::Value;
use std::collections::HashMap;

use hkdf::Hkdf;
use iw_core::{KDF_SALT_GENESIS, KDF_SALT_INTEGRITY};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use zeroize::Zeroize;

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
    },
    /// Upgrades legacy pre-v1.3 GDPR [REDACTED] tombstones to keyed GDPR_HMAC tags
    MigrateGdpr {
        /// Path to the SQLite audit database
        #[arg(short, long, default_value = "audit.db")]
        db: String,
    },
}

fn require_pepper() -> SecretString {
    let pepper_env = std::env::var("WARDEN_PEPPER").unwrap_or_else(|_| {
        eprintln!(
            "WARDEN_PEPPER environment variable is missing. This is required for verification."
        );
        std::process::exit(1);
    });
    SecretString::from(pepper_env)
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Report { db } => {
            if let Err(e) = generate_report(db) {
                eprintln!("Error generating report: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Verify { db } => {
            let secret_pepper = require_pepper();
            if let Err(e) = verify_integrity(db, &secret_pepper) {
                eprintln!("Error verifying integrity: {}", e);
                std::process::exit(1);
            }
        }
        Commands::MigrateGdpr { db } => {
            let secret_pepper = require_pepper();
            if let Err(e) = migrate_gdpr_tombstones(db, &secret_pepper) {
                eprintln!("Error migrating GDPR tombstones: {}", e);
                std::process::exit(1);
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
    sorted_rules.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (rule, count) in sorted_rules {
        println!("  - {}: {} hits", rule, count);
    }
    println!("\n=============================================\n");

    Ok(())
}

fn derive_audit_keys(pepper: &SecretString) -> rusqlite::Result<([u8; 32], [u8; 32])> {
    let hk = Hkdf::<Sha256>::new(None, pepper.expose_secret().as_bytes());
    let mut hmac_key_bytes = [0u8; 32];
    if hk.expand(KDF_SALT_INTEGRITY, &mut hmac_key_bytes).is_err() {
        hmac_key_bytes.zeroize();
        return Err(rusqlite::Error::InvalidQuery);
    }

    let mut genesis_hash = [0u8; 32];
    if hk.expand(KDF_SALT_GENESIS, &mut genesis_hash).is_err() {
        hmac_key_bytes.zeroize();
        genesis_hash.zeroize();
        return Err(rusqlite::Error::InvalidQuery);
    }

    Ok((hmac_key_bytes, genesis_hash))
}

fn migrate_gdpr_tombstones(db_path: &str, pepper: &SecretString) -> rusqlite::Result<()> {
    let conn = Connection::open(db_path)?;
    let (mut hmac_key_bytes, mut genesis_hash) = derive_audit_keys(pepper)?;

    let res = iw_core::audit::migrate_legacy_gdpr_tombstones(
        &conn,
        db_path,
        &genesis_hash,
        &hmac_key_bytes,
    );
    hmac_key_bytes.zeroize();
    genesis_hash.zeroize();

    match res {
        Ok(migrated) => {
            println!(
                "Migrated {} legacy GDPR tombstone record(s) in {}.",
                migrated, db_path
            );
            Ok(())
        }
        Err(msg) => {
            eprintln!("GDPR tombstone migration failed: {}", msg);
            std::process::exit(1);
        }
    }
}

fn verify_integrity(db_path: &str, pepper: &SecretString) -> rusqlite::Result<()> {
    let conn = Connection::open(db_path)?;
    let (mut hmac_key_bytes, mut genesis_hash) = derive_audit_keys(pepper)?;

    println!("\n=============================================");
    println!("⛓️  IRONWARDEN TAMPER-CHECK INTEGRITY TOOL ⛓️");
    println!("=============================================\n");

    let verification = iw_core::audit::verify_audit_chain_diagnostic(
        &conn,
        db_path,
        &genesis_hash,
        &hmac_key_bytes,
    );
    hmac_key_bytes.zeroize();
    genesis_hash.zeroize();

    match verification {
        Ok(summary) => {
            for failure in &summary.failures {
                println!("❌ {}", failure);
            }
            println!("✅ Verified Intact Logs: {}", summary.verified_count);
            println!(
                "📦 Verified Archived Logs: {} (Ephemeral data purged)",
                summary.archived_count
            );
            if summary.gdpr_redacted_count > 0 {
                println!(
                    "🔒 GDPR Shredded Records in Chain: {}",
                    summary.gdpr_redacted_count
                );
            }

            if summary.failures.is_empty() {
                println!("\n✨ STATUS: CHAIN INTACT ✨");
                println!("=============================================\n");
            } else {
                println!(
                    "\n🚨 STATUS: CHAIN CORRUPTED ({} records tampered) 🚨",
                    summary.failures.len()
                );
                println!("=============================================\n");
                std::process::exit(1);
            }
        }
        Err(msg) => {
            println!("❌ VERIFICATION FAILED: {}", msg);
            println!("\n🚨 STATUS: CHAIN CORRUPTED (1 records tampered) 🚨");
            println!("=============================================\n");
            std::process::exit(1);
        }
    }

    Ok(())
}
