//! Read a server's `SSH_MSG_KEXINIT` (RFC 4253 sections 4.2, 6 and 7.1).
//!
//! Both sides send their identification string and then `KEXINIT` in the clear, before any
//! key exchange; the probe sends its identification, reads the server's, reads one binary
//! packet and disconnects. Nothing is authenticated and no key exchange happens.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::kex::{KexClass, classify_kex};

/// RFC 4253 section 6.1: implementations must handle packets up to 35000 bytes.
const MAX_PACKET: usize = 35_000;
const SSH_MSG_KEXINIT: u8 = 20;

/// The algorithm lists of a `KEXINIT` message, in the sender's order of preference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexInit {
    /// Key exchange algorithms.
    pub kex: Vec<String>,
    /// Host key (signature) algorithms.
    pub host_keys: Vec<String>,
    /// Ciphers, client to server.
    pub ciphers_client_to_server: Vec<String>,
    /// Ciphers, server to client.
    pub ciphers_server_to_client: Vec<String>,
    /// MACs, client to server.
    pub macs_client_to_server: Vec<String>,
    /// MACs, server to client.
    pub macs_server_to_client: Vec<String>,
}

/// What a server offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerOffer {
    /// The server's identification string, e.g. `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13`.
    pub identification: String,
    /// Its `KEXINIT` lists.
    pub kexinit: KexInit,
}

impl ServerOffer {
    /// The offered hybrid post-quantum key exchanges, in the server's order.
    pub fn post_quantum_kex(&self) -> Vec<&str> {
        self.kexinit
            .kex
            .iter()
            .map(String::as_str)
            .filter(|k| classify_kex(k).is_post_quantum())
            .collect()
    }

    /// Does the server offer an ML-KEM hybrid (preferred over sntrup761)?
    pub fn offers_ml_kem(&self) -> bool {
        self.kexinit
            .kex
            .iter()
            .any(|k| classify_kex(k) == KexClass::HybridMlKem)
    }

    /// Does the server support strict key exchange (the Terrapin, CVE-2023-48795, fix)?
    pub fn strict_kex(&self) -> bool {
        self.kexinit
            .kex
            .iter()
            .any(|k| k == "kex-strict-s-v00@openssh.com")
    }
}

/// Probe failure.
#[derive(Debug)]
pub enum ProbeError {
    /// Network error or timeout.
    Io(io::Error),
    /// The peer did not speak SSH 2 as expected.
    Protocol(&'static str),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::Io(e) => write!(f, "{e}"),
            ProbeError::Protocol(what) => write!(f, "not an SSH 2 server: {what}"),
        }
    }
}

impl std::error::Error for ProbeError {}

impl From<io::Error> for ProbeError {
    fn from(e: io::Error) -> Self {
        ProbeError::Io(e)
    }
}

/// Connect to `address` (`host`, `host:port`, `[v6]:port`; port 22 by default) and read the
/// server's key exchange offer. `timeout` bounds the connection and each read.
pub fn probe(address: &str, timeout: Duration) -> Result<ServerOffer, ProbeError> {
    let with_port = with_default_port(address);
    let mut last = io::Error::new(io::ErrorKind::NotFound, "address did not resolve");
    for addr in with_port.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return read_offer(stream, timeout),
            Err(e) => last = e,
        }
    }
    Err(ProbeError::Io(last))
}

/// `host` -> `host:22`, `::1` -> `[::1]:22`; addresses with a port are kept.
fn with_default_port(address: &str) -> String {
    use std::net::{IpAddr, SocketAddr};
    if address.parse::<SocketAddr>().is_ok() {
        address.to_owned()
    } else if address.starts_with('[') && address.ends_with(']') {
        format!("{address}:22")
    } else if let Ok(IpAddr::V6(v6)) = address.parse::<IpAddr>() {
        format!("[{v6}]:22")
    } else if address.matches(':').count() == 1 {
        address.to_owned()
    } else {
        format!("{address}:22")
    }
}

fn read_offer(mut stream: TcpStream, timeout: Duration) -> Result<ServerOffer, ProbeError> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(b"SSH-2.0-vpqc_probe\r\n")?;
    // RFC 4253 4.2: the server may send other lines before its identification string.
    let mut identification = None;
    for _ in 0..64 {
        let line = read_line(&mut stream)?;
        if line.starts_with("SSH-2.0-") || line.starts_with("SSH-1.99-") {
            identification = Some(line);
            break;
        }
        if line.starts_with("SSH-") {
            return Err(ProbeError::Protocol("server only speaks SSH 1"));
        }
    }
    let identification = identification.ok_or(ProbeError::Protocol("no identification string"))?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if !(5..=MAX_PACKET).contains(&len) {
        return Err(ProbeError::Protocol("bad packet length"));
    }
    let mut packet = vec![0u8; len];
    stream.read_exact(&mut packet)?;
    let padding = packet[0] as usize;
    if padding < 4 || padding + 1 > len {
        return Err(ProbeError::Protocol("bad padding length"));
    }
    let kexinit = parse_kexinit(&packet[1..len - padding])?;
    Ok(ServerOffer {
        identification,
        kexinit,
    })
}

/// One CR LF (or LF) terminated line of at most 255 bytes, without the terminator.
fn read_line(stream: &mut TcpStream) -> Result<String, ProbeError> {
    let mut line = Vec::new();
    loop {
        let mut b = [0u8; 1];
        stream.read_exact(&mut b)?;
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
        if line.len() > 255 {
            return Err(ProbeError::Protocol("line too long"));
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| ProbeError::Protocol("identification is not UTF-8"))
}

/// Parse the payload of an `SSH_MSG_KEXINIT` packet.
pub fn parse_kexinit(payload: &[u8]) -> Result<KexInit, ProbeError> {
    let bad = ProbeError::Protocol;
    let (&msg, rest) = payload.split_first().ok_or(bad("empty packet"))?;
    if msg != SSH_MSG_KEXINIT {
        return Err(bad("first packet is not KEXINIT"));
    }
    let mut rest = rest.get(16..).ok_or(bad("truncated KEXINIT"))?; // cookie
    let mut lists = Vec::with_capacity(10);
    for _ in 0..10 {
        let len_bytes: [u8; 4] = rest
            .get(..4)
            .ok_or(bad("truncated KEXINIT"))?
            .try_into()
            .expect("4 bytes");
        let len = u32::from_be_bytes(len_bytes) as usize;
        let raw = rest.get(4..4 + len).ok_or(bad("truncated name-list"))?;
        rest = &rest[4 + len..];
        let text = std::str::from_utf8(raw).map_err(|_| bad("name-list is not ASCII"))?;
        let names: Vec<String> = if text.is_empty() {
            Vec::new()
        } else {
            text.split(',').map(str::to_owned).collect()
        };
        if names
            .iter()
            .any(|n| n.is_empty() || n.len() > 64 || !n.bytes().all(|b| (0x21..=0x7e).contains(&b)))
        {
            return Err(bad("invalid algorithm name"));
        }
        lists.push(names);
    }
    // first_kex_packet_follows (boolean) and a reserved uint32.
    if rest.len() < 5 {
        return Err(bad("truncated KEXINIT"));
    }
    let mut it = lists.into_iter();
    let mut next = || it.next().expect("ten lists");
    let kex = next();
    let host_keys = next();
    let ciphers_client_to_server = next();
    let ciphers_server_to_client = next();
    let macs_client_to_server = next();
    let macs_server_to_client = next();
    Ok(KexInit {
        kex,
        host_keys,
        ciphers_client_to_server,
        ciphers_server_to_client,
        macs_client_to_server,
        macs_server_to_client,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port() {
        assert_eq!(with_default_port("example.com"), "example.com:22");
        assert_eq!(with_default_port("example.com:2222"), "example.com:2222");
        assert_eq!(with_default_port("10.0.0.1"), "10.0.0.1:22");
        assert_eq!(with_default_port("::1"), "[::1]:22");
        assert_eq!(with_default_port("[::1]"), "[::1]:22");
        assert_eq!(with_default_port("[::1]:2222"), "[::1]:2222");
    }
}
