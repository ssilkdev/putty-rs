use putty_config::{Conf, SessionStorage, FileStorage};
use putty_fips::run_fips_self_tests;
use std::env;
use std::io::{self, Write};
use std::process::exit;

fn main() {
    println!("=====================================================");
    println!("        PuTTY in Rust (Release 0.85)                 ");
    println!("   FIPS 140-3 Cryptographic Mode & Session Manager    ");
    println!("=====================================================");

    let storage_dir = dirs_or_temp();
    let storage = FileStorage::new(&storage_dir).expect("Failed to initialize session storage");

    let sessions = storage.list_sessions().unwrap_or_default();
    println!("\nSaved Sessions in {}:", storage_dir.display());
    if sessions.is_empty() {
        println!("  (No saved sessions found. Creating 'Default Settings')");
        let def = Conf::default();
        let _ = storage.save_session(&def);
    } else {
        for (idx, name) in sessions.iter().enumerate() {
            println!("  [{}] {}", idx + 1, name);
        }
    }

    let mut fips_active = env::var("PUTTY_FIPS_MODE").map_or(false, |v| v == "1" || v.eq_ignore_ascii_case("true"));

    println!("\nFIPS 140-3 Mode: {}", if fips_active { "ENABLED [Strict]" } else { "DISABLED" });
    println!("Options:");
    println!("  [1] Launch session");
    println!("  [2] Toggle FIPS 140-3 mode");
    println!("  [3] Run FIPS 140-3 Power-On Self Tests (POST / KAT)");
    println!("  [4] Exit");

    print!("\nSelect option [1-4]: ");
    let _ = io::stdout().flush();

    let mut choice = String::new();
    if io::stdin().read_line(&mut choice).is_ok() {
        match choice.trim() {
            "2" => {
                fips_active = !fips_active;
                println!("FIPS 140-3 mode is now: {}", if fips_active { "ENABLED" } else { "DISABLED" });
            }
            "3" => {
                println!("Running FIPS 140-3 KATs...");
                match run_fips_self_tests() {
                    Ok(_) => println!("ALL POWER-ON SELF-TESTS PASSED."),
                    Err(e) => eprintln!("SELF-TEST FAILURE: {}", e),
                }
            }
            "1" => {
                println!("Launching default session...");
            }
            _ => {
                println!("Exiting PuTTY.");
                exit(0);
            }
        }
    }
}

fn dirs_or_temp() -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push("putty_rs_sessions");
    dir
}
