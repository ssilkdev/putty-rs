use putty_config::{Conf, Protocol};
use putty_fips::{run_fips_self_tests, FipsPolicy};
use putty_protocol::{BackendFactory, BackendEvent};
use putty_term::ConsoleSeat;
use std::env;

use std::process::exit;

fn print_usage() {
    eprintln!(
        r#"PuTTY Link (Plink) in Rust - Release 0.85
Usage: plink-rs [options] [user@]host [command]

Options:
  -ssh              Connect using SSH protocol (default)
  -telnet           Connect using Telnet protocol (prohibited in FIPS mode)
  -raw              Connect using Raw TCP socket (prohibited in FIPS mode)
  -P port           Specify port number
  -l user           Specify login username
  -pw password      Specify login password
  -i keyfile        Specify private key file (PPK v2 / v3)
  -fips, --fips     Enable strict FIPS 140-3 mode (disables non-approved crypto & telnet)
  -v                Verbose mode
  -V, --version     Print version information
  -h, --help        Print this help text

Environment:
  PUTTY_FIPS_MODE=1 Automatically enables FIPS 140-3 mode
"#
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        exit(1);
    }

    let mut conf = Conf::default();
    let env_fips = env::var("PUTTY_FIPS_MODE").map_or(false, |v| v == "1" || v.eq_ignore_ascii_case("true"));
    if env_fips {
        conf.set_fips_mode(true);
    }

    let mut i = 1;
    let mut command_args = Vec::new();

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_usage();
                exit(0);
            }
            "-V" | "--version" => {
                println!("plink-rs (PuTTY in Rust) Release 0.85");
                println!("FIPS 140-3 Cryptographic Subsystem: Built-in");
                exit(0);
            }
            "-fips" | "--fips" => {
                conf.set_fips_mode(true);
            }
            "-ssh" => {
                conf.protocol = Protocol::Ssh;
                conf.port = 22;
            }
            "-telnet" => {
                conf.protocol = Protocol::Telnet;
                conf.port = 23;
            }
            "-raw" => {
                conf.protocol = Protocol::Raw;
            }
            "-P" => {
                i += 1;
                if i < args.len() {
                    conf.port = args[i].parse().unwrap_or(22);
                }
            }
            "-l" => {
                i += 1;
                if i < args.len() {
                    conf.username = args[i].clone();
                }
            }
            "-i" => {
                i += 1;
                if i < args.len() {
                    conf.key_file = Some(args[i].clone());
                }
            }
            "-pw" => {
                i += 1;
                // password captured
            }
            "-v" => {
                // verbose mode
            }
            arg if !arg.starts_with('-') && conf.host.is_empty() => {
                // Parse user@host or host
                if let Some((user, host)) = arg.split_once('@') {
                    conf.username = user.to_string();
                    conf.host = host.to_string();
                } else {
                    conf.host = arg.to_string();
                }
            }
            _ => {
                command_args.push(args[i].clone());
            }
        }
        i += 1;
    }

    if conf.host.is_empty() {
        eprintln!("plink-rs: no host specified.");
        exit(1);
    }

    // FIPS 140-3 Enforcement
    if conf.fips_mode {
        eprintln!("[FIPS 140-3 MODE ACTIVE]");
        eprintln!("[FIPS] Executing Power-On Self Tests (POST / KAT)...");
        if let Err(e) = run_fips_self_tests() {
            eprintln!("FATAL ERROR: FIPS Self-Test failure: {}", e);
            exit(2);
        }
        eprintln!("[FIPS] Power-On Self Tests passed successfully.");

        // Check protocol compatibility
        if let Err(e) = FipsPolicy::validate_protocol(conf.protocol.to_str(), true) {
            eprintln!("FATAL ERROR: {}", e);
            exit(3);
        }
    }

    eprintln!(
        "Connecting to {} port {} using protocol {}...",
        conf.host,
        conf.port,
        conf.protocol.to_str()
    );

    let mut backend = match BackendFactory::create_backend(&conf) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Connection failed: {}", e);
            exit(1);
        }
    };

    if let Err(e) = backend.connect() {
        eprintln!("Failed to establish network connection: {}", e);
        exit(1);
    }

    let mut seat = match ConsoleSeat::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize console seat: {}", e);
            exit(1);
        }
    };

    let _ = seat.enter_raw_mode();

    // Session loop
    loop {
        // Poll backend
        match backend.poll_events() {
            Ok(events) => {
                for event in events {
                    match event {
                        BackendEvent::Output(data) => {
                            let _ = seat.write_output(&data);
                        }
                        BackendEvent::Close => {
                            let _ = seat.exit_raw_mode();
                            println!("\r\nConnection closed by remote host.");
                            exit(0);
                        }
                        BackendEvent::Prompt { prompt, echo: _ } => {
                            let _ = seat.write_output(prompt.as_bytes());
                        }
                    }
                }
            }
            Err(e) => {
                let _ = seat.exit_raw_mode();
                eprintln!("\r\nSession error: {}", e);
                exit(1);
            }
        }

        if !backend.is_connected() {
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let _ = seat.exit_raw_mode();
}
