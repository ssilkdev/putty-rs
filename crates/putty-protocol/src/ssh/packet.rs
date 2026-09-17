use byteorder::{BigEndian, ByteOrder};

pub const SSH_MSG_DISCONNECT: u8 = 1;
pub const SSH_MSG_IGNORE: u8 = 2;
pub const SSH_MSG_KEXINIT: u8 = 20;
pub const SSH_MSG_NEWKEYS: u8 = 21;
pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;

#[derive(Debug, Clone)]
pub struct SshPacket {
    pub msg_type: u8,
    pub payload: Vec<u8>,
}

impl SshPacket {
    pub fn new(msg_type: u8, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    /// Encode into unencrypted SSH Binary Packet Protocol (RFC 4253 BPP)
    pub fn encode_unencrypted(&self) -> Vec<u8> {
        let block_size = 8;
        let payload_len = 1 + self.payload.len();
        let padding_len = block_size - ((4 + 1 + payload_len) % block_size);
        let padding_len = if padding_len < 4 { padding_len + block_size } else { padding_len };
        let packet_length = 1 + payload_len + padding_len;

        let mut out = Vec::with_capacity(4 + packet_length);
        out.extend_from_slice(&(packet_length as u32).to_be_bytes());
        out.push(padding_len as u8);
        out.push(self.msg_type);
        out.extend_from_slice(&self.payload);
        out.extend(vec![0u8; padding_len]);
        out
    }
}

pub struct PacketReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> PacketReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn read_byte(&mut self) -> Option<u8> {
        if self.pos < self.data.len() {
            let b = self.data[self.pos];
            self.pos += 1;
            Some(b)
        } else {
            None
        }
    }

    pub fn read_u32(&mut self) -> Option<u32> {
        if self.pos + 4 <= self.data.len() {
            let val = BigEndian::read_u32(&self.data[self.pos..self.pos + 4]);
            self.pos += 4;
            Some(val)
        } else {
            None
        }
    }

    pub fn read_string(&mut self) -> Option<&'a [u8]> {
        let len = self.read_u32()? as usize;
        if self.pos + len <= self.data.len() {
            let slice = &self.data[self.pos..self.pos + len];
            self.pos += len;
            Some(slice)
        } else {
            None
        }
    }

    pub fn read_string_utf8(&mut self) -> Option<String> {
        let slice = self.read_string()?;
        String::from_utf8(slice.to_vec()).ok()
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
}

pub struct PacketWriter {
    buf: Vec<u8>,
}

impl PacketWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn write_byte(&mut self, b: u8) {
        self.buf.push(b);
    }

    pub fn write_bool(&mut self, b: bool) {
        self.buf.push(if b { 1 } else { 0 });
    }

    pub fn write_u32(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    pub fn write_string(&mut self, s: &[u8]) {
        self.write_u32(s.len() as u32);
        self.buf.extend_from_slice(s);
    }

    pub fn write_name_list(&mut self, names: &[&str]) {
        let joined = names.join(",");
        self.write_string(joined.as_bytes());
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}
