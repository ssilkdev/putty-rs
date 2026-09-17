pub mod packet;

use crate::backend::{Backend, BackendEvent, ProtocolError};
use packet::*;
use putty_config::Conf;

use putty_fips::{FipsError, FipsPolicy};
use std::io::{Read, Write};
use std::net::TcpStream;

#[allow(dead_code)]
pub struct SshBackend {
    conf: Conf,
    stream: Option<TcpStream>,
    connected: bool,
    server_version: String,
    client_version: String,
    channel_id: u32,
    authenticated: bool,
}

impl SshBackend {
    pub fn new(conf: Conf) -> Result<Self, ProtocolError> {
        if conf.fips_mode {
            FipsPolicy::validate_protocol("ssh", true)?;
        }
        Ok(Self {
            conf,
            stream: None,
            connected: false,
            server_version: String::new(),
            client_version: "SSH-2.0-PuTTY-Rust-0.85".to_string(),
            channel_id: 0,
            authenticated: false,
        })
    }

    /// Build the client KEXINIT packet payload, applying FIPS filtering if FIPS mode is enabled
    pub fn build_kexinit(&self) -> Result<Vec<u8>, ProtocolError> {
        let fips = self.conf.fips_mode;
        let mut writer = PacketWriter::new();

        // Cookie (16 random bytes)
        let cookie = [0x55u8; 16];
        for b in &cookie {
            writer.write_byte(*b);
        }

        // KEX algorithms
        let all_kex = &[
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "diffie-hellman-group14-sha256",
            "curve25519-sha256",
        ];
        let kex_list = FipsPolicy::filter_algorithms(all_kex, FipsPolicy::APPROVED_KEX, fips);
        writer.write_name_list(&kex_list);

        // Server host key algorithms
        let all_hk = &[
            "rsa-sha2-512",
            "rsa-sha2-256",
            "ecdsa-sha2-nistp256",
            "ssh-ed25519",
            "ssh-rsa",
        ];
        let hk_list = FipsPolicy::filter_algorithms(all_hk, FipsPolicy::APPROVED_HOSTKEYS, fips);
        writer.write_name_list(&hk_list);

        // Encryption ciphers (client to server & server to client)
        let all_ciphers = &[
            "aes256-gcm@openssh.com",
            "aes128-gcm@openssh.com",
            "aes256-ctr",
            "aes192-ctr",
            "aes128-ctr",
            "chacha20-poly1305@openssh.com",
        ];
        let cipher_list = FipsPolicy::filter_algorithms(all_ciphers, FipsPolicy::APPROVED_CIPHERS, fips);
        writer.write_name_list(&cipher_list);
        writer.write_name_list(&cipher_list);

        // MAC algorithms (client to server & server to client)
        let all_macs = &[
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
            "hmac-sha1",
        ];
        let mac_list = FipsPolicy::filter_algorithms(all_macs, FipsPolicy::APPROVED_MACS, fips);
        writer.write_name_list(&mac_list);
        writer.write_name_list(&mac_list);

        // Compression (none)
        writer.write_name_list(&["none"]);
        writer.write_name_list(&["none"]);

        // Languages
        writer.write_name_list(&[]);
        writer.write_name_list(&[]);

        // first_kex_packet_follows = false
        writer.write_bool(false);
        // reserved u32 = 0
        writer.write_u32(0);

        Ok(writer.into_vec())
    }

    /// Negotiate algorithms and ensure strict FIPS 140-3 compliance
    pub fn negotiate_algorithm(
        client_list: &[&str],
        server_list: &[&str],
        fips_mode: bool,
        validator: fn(&str, bool) -> Result<(), FipsError>,
    ) -> Result<String, ProtocolError> {
        for client_item in client_list {
            if server_list.contains(client_item) {
                // Validate against FIPS policy
                validator(client_item, fips_mode)?;
                return Ok(client_item.to_string());
            }
        }
        Err(ProtocolError::Ssh("No compatible cryptographic algorithm found".into()))
    }
}

impl Backend for SshBackend {
    fn connect(&mut self) -> Result<(), ProtocolError> {
        let addr = format!("{}:{}", self.conf.host, self.conf.port);
        let mut stream = TcpStream::connect(&addr)?;

        // Send client version string
        stream.write_all(format!("{}\r\n", self.client_version).as_bytes())?;
        stream.flush()?;

        // Send KEXINIT
        let kex_payload = self.build_kexinit()?;
        let packet = SshPacket::new(SSH_MSG_KEXINIT, kex_payload);
        stream.write_all(&packet.encode_unencrypted())?;
        stream.flush()?;

        stream.set_nonblocking(true)?;
        self.stream = Some(stream);
        self.connected = true;
        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        if let Some(ref mut stream) = self.stream {
            let mut writer = PacketWriter::new();
            writer.write_u32(self.channel_id);
            writer.write_string(data);
            let packet = SshPacket::new(SSH_MSG_CHANNEL_DATA, writer.into_vec());
            stream.write_all(&packet.encode_unencrypted())?;
            stream.flush()?;
        }
        Ok(())
    }

    fn poll_events(&mut self) -> Result<Vec<BackendEvent>, ProtocolError> {
        let mut events = Vec::new();
        if let Some(ref mut stream) = self.stream {
            let mut buf = [0u8; 4096];
            match stream.read(&mut buf) {
                Ok(0) => {
                    self.connected = false;
                    events.push(BackendEvent::Close);
                }
                Ok(n) => {
                    events.push(BackendEvent::Output(buf[..n].to_vec()));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(ProtocolError::Io(e)),
            }
        }
        Ok(events)
    }

    fn resize(&mut self, width: u16, height: u16) -> Result<(), ProtocolError> {
        if let Some(ref mut stream) = self.stream {
            let mut writer = PacketWriter::new();
            writer.write_u32(self.channel_id);
            writer.write_string(b"window-change");
            writer.write_bool(false); // want_reply
            writer.write_u32(width as u32);
            writer.write_u32(height as u32);
            writer.write_u32(0); // pixel width
            writer.write_u32(0); // pixel height
            let packet = SshPacket::new(SSH_MSG_CHANNEL_REQUEST, writer.into_vec());
            let _ = stream.write_all(&packet.encode_unencrypted());
        }
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), ProtocolError> {
        if let Some(ref mut stream) = self.stream {
            let mut writer = PacketWriter::new();
            writer.write_u32(11); // SSH_DISCONNECT_BY_APPLICATION
            writer.write_string(b"PuTTY Rust session closed");
            writer.write_string(b"");
            let packet = SshPacket::new(SSH_MSG_DISCONNECT, writer.into_vec());
            let _ = stream.write_all(&packet.encode_unencrypted());
        }
        self.connected = false;
        self.stream = None;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}
