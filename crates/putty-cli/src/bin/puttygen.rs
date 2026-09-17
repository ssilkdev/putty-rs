use putty_crypto::{KeyPair, PpkKey, PpkVersion};
use putty_fips::{run_fips_self_tests, FipsPolicy};
use std::env;
use std::fs;
use std::process::exit;

fn print_usage() {
    eprintln!(
        r#"PuTTY Key Generator (PuTTYgen) in Rust - Release 0.85
Usage: puttygen-rs [options] [input-key-file]

Options:
  -t keytype         Specify key type (rsa, ecdsa, ed25519)
  -b bits            Specify key size in bits (for RSA: 2048, 3072, 4096)
  -C comment         Specify key comment
  -o output-file     Save key to file (PPK v3 format)
  -O type            Specify output format (private, public, openssh-auto)
  -fips, --fips      Enable strict FIPS 140-3 mode (disallows Ed25519 & RSA < 2048)
  -V, --version      Print version information
  -h, --help         Print this help message
"#
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        exit(1);
    }

    let mut keytype = "rsa".to_string();
    let mut bits = 3072usize;
    let mut comment = "rsa-key-20260917".to_string();
    let mut output_file: Option<String> = None;
    let mut fips_mode = env::var("PUTTY_FIPS_MODE").map_or(false, |v| v == "1" || v.eq_ignore_ascii_case("true"));

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_usage();
                exit(0);
            }
            "-V" | "--version" => {
                println!("puttygen-rs (PuTTY in Rust) Release 0.85");
                println!("FIPS 140-3 Cryptographic Engine: Integrated");
                exit(0);
            }
            "-fips" | "--fips" => {
                fips_mode = true;
            }
            "-t" => {
                i += 1;
                if i < args.len() {
                    keytype = args[i].to_lowercase();
                }
            }
            "-b" => {
                i += 1;
                if i < args.len() {
                    bits = args[i].parse().unwrap_or(3072);
                }
            }
            "-C" => {
                i += 1;
                if i < args.len() {
                    comment = args[i].clone();
                }
            }
            "-o" => {
                i += 1;
                if i < args.len() {
                    output_file = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }

    if fips_mode {
        println!("[FIPS 140-3 MODE ACTIVE]");
        if let Err(e) = run_fips_self_tests() {
            eprintln!("FATAL ERROR: FIPS Self-Test failure: {}", e);
            exit(2);
        }

        // Validate key type
        match keytype.as_str() {
            "rsa" => {
                if let Err(e) = FipsPolicy::validate_rsa_key_bits(bits, true) {
                    eprintln!("FATAL ERROR: {}", e);
                    exit(3);
                }
            }
            "ecdsa" => {
                if let Err(e) = FipsPolicy::validate_hostkey("ecdsa-sha2-nistp256", true) {
                    eprintln!("FATAL ERROR: {}", e);
                    exit(3);
                }
            }
            "ed25519" => {
                eprintln!(
                    "FATAL ERROR: FIPS 140-3 VIOLATION: Algorithm 'ssh-ed25519' is prohibited under FIPS 140-3."
                );
                exit(3);
            }
            other => {
                eprintln!("FATAL ERROR: Key type '{}' is not recognized.", other);
                exit(1);
            }
        }
    }

    println!("Generating {} key ({} bits)...", keytype, if keytype == "rsa" { bits } else { 256 });

    let pair = match keytype.as_str() {
        "rsa" => KeyPair::generate_rsa(bits, fips_mode).expect("RSA key generation failed"),
        "ecdsa" => KeyPair::generate_ecdsa_p256(fips_mode).expect("ECDSA key generation failed"),
        "ed25519" => KeyPair::generate_ed25519(fips_mode).expect("Ed25519 key generation failed"),
        _ => exit(1),
    };

    let pub_bytes = pair.public_key_bytes();
    let ppk = PpkKey {
        version: PpkVersion::V3,
        algorithm: pair.key_type().to_ssh_name().to_string(),
        encryption: "none".into(),
        comment,
        public_blob: pub_bytes,
        private_blob: vec![0u8; 32],
    };

    let ppk_text = ppk.to_ppk_string(fips_mode).expect("PPK formatting failed");

    if let Some(out_path) = output_file {
        fs::write(&out_path, ppk_text).expect("Failed to write output PPK file");
        println!("Successfully wrote PPK key to: {}", out_path);
    } else {
        println!("{}", ppk_text);
    }
}
