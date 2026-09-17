# PuTTY (Rust Edition) with FIPS 140-3 Mode

A modern, memory-safe rewrite of PuTTY in Rust featuring a sleek Windows 11 Fluent minimalist native GUI, Windows DPAPI credential encryption at rest, and strict NIST FIPS 140-3 cryptographic policy enforcement.

---

## Key Features

### Minimalist Fluent Native GUI
- **Distraction-Free Startup**: Compact footprint (~500x430px) presenting only essential connection parameters (Saved session selector, Host, Port, Username, Password, and Private Key).
- **Windows 11 Dark Immersion**: Deep slate dark theme with hardware-accelerated DWM titlebar dark mode and clean typography using Segoe UI.
- **Native Subsystem**: Compiled with `#![windows_subsystem = "windows"]` ensuring no auxiliary console window is spawned when launching the GUI.
- **Non-Intrusive Menus**: Advanced tools and policy controls are tucked into top-level menus (`Session`, `Security`, `Tools`, `Protocol`, `Help`).
  - **PuTTYgen Key Generator**: Generate RSA (3072-bit), ECDSA (NIST P-256), and Ed25519 key pairs; export to PPK v3 format; and copy OpenSSH public keys directly to clipboard.
  - **Session Manager**: Search, filter, load, save as, and delete saved sessions.
  - **FIPS 140-3 Cryptographic Matrix**: Comprehensive policy audit display and live execution of all 5 power-on Known Answer Tests (KAT).
  - **VT100 Terminal Console**: Embedded test console with phosphor green output and command history.
  - **Remote SSH Verification**: Non-blocking reachability and host key probe.

### Security & Credential Protection
- **Windows DPAPI At-Rest Encryption**: Saved session passwords are automatically protected using the Windows Data Protection API (DPAPI) with user-scoped AES keys. Cleartext passwords are never persisted to disk.
- **Strict FIPS 140-3 Mode**:
  - **Approved**: AES-128-CTR, AES-256-CTR, AES-128-GCM, AES-256-GCM, SHA-256, SHA-512, HMAC-SHA2-256, HMAC-SHA2-512, ECDH NIST P-256 (`prime256v1`), RSA >= 2048-bit, and SSH-2.
  - **Blocked**: Telnet, Raw TCP, ChaCha20-Poly1305, 3DES, Blowfish, MD5, SHA-1, and Curve25519.

---

## Workspace Architecture

The workspace is organized into modular crates:

| Crate | Description |
|---|---|
| `crates/putty-gui` | Native Win32 / GDI / DWM GUI application with owner-draw Fluent controls |
| `crates/putty-fips` | NIST FIPS 140-3 policy validation engine and Known Answer Tests (KAT) |
| `crates/putty-crypto` | Cryptographic primitives, key exchange sessions, and PPK v3 generation |
| `crates/putty-config` | Session configuration loader/saver with Windows DPAPI encryption vault |
| `crates/putty-protocol` | SSH-2, Telnet, and Raw backend protocol abstractions |
| `crates/putty-term` | VT100 terminal emulation and screen buffer handling |
| `crates/putty-cli` | Command-line utilities (`putty`, `plink`, `puttygen`) |

---

## Building and Testing

### Prerequisites
- [Rust](https://rustup.rs/) (1.75+ recommended)
- Windows 10/11 (64-bit)

### Run Unit Tests
```bash
cargo test --workspace
```

### Build Release GUI Binary
```bash
cargo build --release -p putty-gui
```
The resulting standalone executable is located at `target/release/putty-gui.exe`.

---

## License
MIT License
