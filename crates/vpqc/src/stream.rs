//! Streaming encryption for data of any size, in constant memory (ADR-0007).
//!
//! ```
//! use std::io::{Read, Write};
//! use vpqc::{Profile, encryption, stream};
//!
//! let keys = encryption::generate(Profile::Standard)?;
//! let mut enc = stream::Encryptor::new(&keys.public, b"backup-2026-09", Vec::new())?;
//! enc.write_all(b"a very large file...")?;
//! let ciphertext = enc.finish()?;
//!
//! let mut dec = stream::Decryptor::new(&keys.secret, b"backup-2026-09", &ciphertext[..])?;
//! let mut plain = Vec::new();
//! dec.read_to_end(&mut plain)?; // an Err means: discard everything read so far
//! assert_eq!(plain, b"a very large file...");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! **Plaintext is released chunk by chunk.** Each chunk is authentic when returned, but a
//! truncated stream is only detected at the end. If a read returns an error, discard all
//! output. [`decrypt_file`] does this for you: it writes to a temporary file and renames it
//! only after the whole stream has been verified.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use subtle::ConstantTimeEq;
use vpqc_core::{AeadId, AlgorithmId, Error, KemId, OsRng, PublicKey, RandomSource, SecretKey};
use vpqc_format::{
    AnyStreamHeader, DEFAULT_CHUNK_LOG, HEADER_MAC_LEN, HeaderScan, MAX_RECIPIENTS,
    MultiStreamHeader, RecipientStanza, StreamHeader,
};
use zeroize::{Zeroize, Zeroizing};

use crate::registry;

const KDF_LABEL: &[u8] = b"vpqc-stream-v1";
/// Multi-recipient stream labels (ADR-0009).
const MULTI_KDF_LABEL: &[u8] = b"vpqc-multistream-v1";
const WRAP_LABEL: &[u8] = b"vpqc-recipient-v1";
const MAC_LABEL: &[u8] = b"vpqc-header-mac-v1";
const TAG_LEN: usize = 16;

/// Stream parameters.
#[derive(Debug, Clone, Copy)]
pub struct StreamOptions {
    /// Chunk size is `2^chunk_log` bytes (10..=24). Default 16 (64 KiB).
    pub chunk_log: u8,
}

impl Default for StreamOptions {
    fn default() -> Self {
        Self {
            chunk_log: DEFAULT_CHUNK_LOG,
        }
    }
}

fn invalid_input(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e)
}

fn decryption_failed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, Error::DecryptionFailed)
}

/// The vpqc error inside an `io::Error` returned by this module, if it is a crypto error
/// (as opposed to an operating system I/O error).
pub fn crypto_error(e: &io::Error) -> Option<&Error> {
    e.get_ref().and_then(|inner| inner.downcast_ref::<Error>())
}

/// `SHAKE256(label || be64(len(header)) || header || be64(len(aad)) || aad || secret)[..32]`.
fn kdf(label: &[u8], header: &[u8], aad: &[u8], secret: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut input = Zeroizing::new(Vec::with_capacity(
        label.len() + 16 + header.len() + aad.len() + secret.len(),
    ));
    input.extend_from_slice(label);
    input.extend_from_slice(&(header.len() as u64).to_be_bytes());
    input.extend_from_slice(header);
    input.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    input.extend_from_slice(aad);
    input.extend_from_slice(secret);
    let mut key = Zeroizing::new([0u8; 32]);
    libcrux_sha3::shake256_ema(&mut *key, &input);
    key
}

fn aead(key: &[u8; 32]) -> io::Result<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(key).map_err(|_| invalid_input(Error::Backend("bad AEAD key")))
}

fn derive_key(header: &[u8], aad: &[u8], shared_secret: &[u8; 32]) -> io::Result<ChaCha20Poly1305> {
    aead(&kdf(KDF_LABEL, header, aad, shared_secret))
}

/// Key that wraps the file key for one recipient: bound to the KEM and its ciphertext.
fn wrap_key(
    kem: KemId,
    kem_ciphertext: &[u8],
    shared_secret: &[u8; 32],
) -> io::Result<ChaCha20Poly1305> {
    aead(&kdf(
        WRAP_LABEL,
        &kem.to_u16().to_be_bytes(),
        kem_ciphertext,
        shared_secret,
    ))
}

/// Header MAC keyed with the file key. It commits to the file key, so recipients who can
/// unwrap it all agree on the same key (and therefore the same plaintext).
fn header_mac(unauthenticated: &[u8], aad: &[u8], file_key: &[u8; 32]) -> [u8; HEADER_MAC_LEN] {
    *kdf(MAC_LABEL, unauthenticated, aad, file_key)
}

/// `be88(counter) || last_flag`.
fn nonce(counter: u64, last: bool) -> Nonce {
    let mut n = [0u8; 12];
    n[3..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = u8::from(last);
    Nonce::from(n)
}

/// Encrypts a stream to a recipient. Write plaintext into it, then call
/// [`Encryptor::finish`]. Dropping it without `finish` leaves an invalid (truncated) stream,
/// which decryption rejects.
pub struct Encryptor<W: Write> {
    inner: W,
    cipher: ChaCha20Poly1305,
    counter: u64,
    chunk: usize,
    buf: Zeroizing<Vec<u8>>,
}

impl<W: Write> Encryptor<W> {
    /// Start a stream with default options. Writes the header to `inner` immediately.
    pub fn new(recipient: &PublicKey, aad: &[u8], inner: W) -> io::Result<Self> {
        Self::with_options(recipient, aad, inner, StreamOptions::default())
    }

    /// Start a stream with explicit options.
    pub fn with_options(
        recipient: &PublicKey,
        aad: &[u8],
        inner: W,
        options: StreamOptions,
    ) -> io::Result<Self> {
        Self::with_rng(recipient, aad, inner, options, &mut OsRng)
    }

    /// [`Encryptor::with_options`] with an explicit randomness source (for tests).
    #[doc(hidden)]
    pub fn with_rng(
        recipient: &PublicKey,
        aad: &[u8],
        mut inner: W,
        options: StreamOptions,
        rng: &mut dyn RandomSource,
    ) -> io::Result<Self> {
        let AlgorithmId::Kem(kem) = recipient.algorithm() else {
            return Err(invalid_input(Error::AlgorithmMismatch));
        };
        let (kem_ciphertext, ss) = registry::kem(kem)
            .and_then(|k| k.encapsulate(recipient, rng))
            .map_err(invalid_input)?;
        let header = StreamHeader {
            kem,
            aead: AeadId::ChaCha20Poly1305,
            chunk_log: options.chunk_log,
            kem_ciphertext,
        };
        let raw = header.encode().map_err(invalid_input)?;
        let cipher = derive_key(&raw, aad, ss.expose())?;
        inner.write_all(&raw)?;
        let chunk = header.chunk_size();
        Ok(Self {
            inner,
            cipher,
            counter: 0,
            chunk,
            buf: Zeroizing::new(Vec::with_capacity(chunk)),
        })
    }

    /// Start a stream that each of `recipients` can decrypt with their own secret key
    /// (1 to 32 distinct keys, possibly of different profiles). Writes the header to `inner`.
    ///
    /// Anyone who can decrypt learns the number of recipients and their KEM algorithms, but
    /// not their identities.
    pub fn to_recipients(
        recipients: &[&PublicKey],
        aad: &[u8],
        inner: W,
        options: StreamOptions,
    ) -> io::Result<Self> {
        Self::to_recipients_with_rng(recipients, aad, inner, options, &mut OsRng)
    }

    /// [`Encryptor::to_recipients`] with an explicit randomness source (for tests).
    #[doc(hidden)]
    pub fn to_recipients_with_rng(
        recipients: &[&PublicKey],
        aad: &[u8],
        inner: W,
        options: StreamOptions,
        rng: &mut dyn RandomSource,
    ) -> io::Result<Self> {
        check_recipients(recipients)?;
        let mut file_key = Zeroizing::new([0u8; 32]);
        rng.fill(&mut *file_key).map_err(invalid_input)?;
        let keys = vec![*file_key; recipients.len()];
        let r = Self::build_multi(
            recipients, &keys, &file_key, &file_key, aad, inner, options, rng,
        );
        keys.into_iter().for_each(|mut k| k.zeroize());
        r
    }

    /// Test hook: a *malicious* header in which recipient `i` unwraps `wrapped[i]`, the MAC is
    /// keyed with `mac_key` and the payload with `payload_key`. Honest encryption uses one
    /// file key for all three; tests use this to show that decryptors reject the rest.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn to_recipients_forged_for_testing(
        recipients: &[&PublicKey],
        wrapped: &[[u8; 32]],
        mac_key: &[u8; 32],
        payload_key: &[u8; 32],
        aad: &[u8],
        inner: W,
        options: StreamOptions,
    ) -> io::Result<Self> {
        Self::build_multi(
            recipients,
            wrapped,
            mac_key,
            payload_key,
            aad,
            inner,
            options,
            &mut OsRng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_multi(
        recipients: &[&PublicKey],
        wrapped_keys: &[[u8; 32]],
        mac_key: &[u8; 32],
        payload_key: &[u8; 32],
        aad: &[u8],
        mut inner: W,
        options: StreamOptions,
        rng: &mut dyn RandomSource,
    ) -> io::Result<Self> {
        let raw = multi_header(
            recipients,
            wrapped_keys,
            mac_key,
            aad,
            options.chunk_log,
            rng,
        )?;
        let cipher = payload_cipher(&raw, aad, payload_key)?;
        inner.write_all(&raw)?;
        let chunk = 1usize << options.chunk_log;
        Ok(Self {
            inner,
            cipher,
            counter: 0,
            chunk,
            buf: Zeroizing::new(Vec::with_capacity(chunk)),
        })
    }

    fn emit(&mut self, last: bool) -> io::Result<()> {
        let ct = self
            .cipher
            .encrypt(
                &nonce(self.counter, last),
                Payload {
                    msg: &self.buf,
                    aad: b"",
                },
            )
            .map_err(|_| invalid_input(Error::Backend("AEAD encryption failed")))?;
        self.inner.write_all(&ct)?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| invalid_input(Error::Format("stream too long")))?;
        self.buf.zeroize();
        Ok(())
    }

    /// Mutable access to the inner writer, e.g. to drain a `Vec<u8>` after each write when
    /// encrypting incrementally (the header is written by the constructor).
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Test helper: emit the buffered data as a *non-final* chunk followed by an empty final
    /// chunk. Authentic but non-canonical; decryptors must reject it.
    #[doc(hidden)]
    pub fn finish_noncanonical_for_testing(mut self) -> io::Result<W> {
        if !self.buf.is_empty() {
            self.emit(false)?;
        }
        self.emit(true)?;
        Ok(self.inner)
    }

    /// Write the final chunk and return the inner writer (not flushed).
    pub fn finish(mut self) -> io::Result<W> {
        self.emit(true)?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for Encryptor<W> {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        let n = data.len();
        while !data.is_empty() {
            // A full buffer is only emitted once more data arrives: the final chunk must be
            // marked as such, and it may be full.
            if self.buf.len() == self.chunk {
                self.emit(false)?;
            }
            let take = (self.chunk - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Verifies and decrypts chunks in order; shared by [`Decryptor`] and [`PushDecryptor`].
struct ChunkOpener {
    cipher: ChaCha20Poly1305,
    counter: u64,
    chunk_ct: usize,
}

impl ChunkOpener {
    fn start(
        secret: &SecretKey,
        aad: &[u8],
        header: &AnyStreamHeader,
        raw: &[u8],
    ) -> io::Result<Self> {
        let cipher = match header {
            AnyStreamHeader::Single(h) => {
                if secret.algorithm() != AlgorithmId::Kem(h.kem) {
                    return Err(invalid_input(Error::AlgorithmMismatch));
                }
                let ss = registry::kem(h.kem)
                    .and_then(|k| k.decapsulate(secret, &h.kem_ciphertext))
                    .map_err(|_| decryption_failed())?;
                derive_key(raw, aad, ss.expose())?
            }
            AnyStreamHeader::Multi(h) => {
                let file_key = unwrap_file_key(secret, aad, h, raw)?;
                payload_cipher(raw, aad, &file_key)?
            }
        };
        Ok(Self {
            cipher,
            counter: 0,
            chunk_ct: header.chunk_size() + TAG_LEN,
        })
    }

    /// Decrypt the next chunk. `last` must be decided from the end of input only.
    fn open(&mut self, ct: &[u8], last: bool) -> io::Result<Vec<u8>> {
        if ct.len() < TAG_LEN || ct.len() > self.chunk_ct {
            return Err(decryption_failed()); // truncated or malformed
        }
        if last && ct.len() == TAG_LEN && self.counter != 0 {
            return Err(decryption_failed()); // an empty final chunk is only valid for empty plaintext
        }
        let pt = self
            .cipher
            .decrypt(&nonce(self.counter, last), Payload { msg: ct, aad: b"" })
            .map_err(|_| decryption_failed())?;
        self.counter = self.counter.checked_add(1).ok_or_else(decryption_failed)?;
        Ok(pt)
    }
}

fn check_recipients(recipients: &[&PublicKey]) -> io::Result<()> {
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(invalid_input(Error::Format(
            "between 1 and 32 recipients required",
        )));
    }
    for (i, a) in recipients.iter().enumerate() {
        if recipients[..i].iter().any(|b| b.as_bytes() == a.as_bytes()) {
            return Err(invalid_input(Error::Format("duplicate recipient")));
        }
    }
    Ok(())
}

/// Encode a multi-recipient header: stanza `i` wraps `wrapped_keys[i]` for `recipients[i]`;
/// the MAC is keyed with `mac_key` (the file key, in honest use).
fn multi_header(
    recipients: &[&PublicKey],
    wrapped_keys: &[[u8; 32]],
    mac_key: &[u8; 32],
    aad: &[u8],
    chunk_log: u8,
    rng: &mut dyn RandomSource,
) -> io::Result<Vec<u8>> {
    let mut stanzas = Vec::with_capacity(recipients.len());
    for (recipient, file_key) in recipients.iter().zip(wrapped_keys) {
        let AlgorithmId::Kem(kem) = recipient.algorithm() else {
            return Err(invalid_input(Error::AlgorithmMismatch));
        };
        let (kem_ciphertext, ss) = registry::kem(kem)
            .and_then(|k| k.encapsulate(recipient, rng))
            .map_err(invalid_input)?;
        let wrapped = wrap_key(kem, &kem_ciphertext, ss.expose())?
            .encrypt(&Nonce::default(), &file_key[..])
            .map_err(|_| invalid_input(Error::Backend("AEAD encryption failed")))?;
        stanzas.push(RecipientStanza {
            kem,
            kem_ciphertext,
            wrapped_key: wrapped.try_into().expect("32-byte key + 16-byte tag"),
        });
    }
    let mut header = MultiStreamHeader {
        aead: AeadId::ChaCha20Poly1305,
        chunk_log,
        recipients: stanzas,
        mac: [0; HEADER_MAC_LEN],
    };
    let unauthenticated = header.encode_unauthenticated().map_err(invalid_input)?;
    header.mac = header_mac(&unauthenticated, aad, mac_key);
    header.encode().map_err(invalid_input)
}

/// The payload key depends on the file key, the stream parameters (the first 8 header bytes:
/// magic, version, kind, AEAD, chunk size) and `aad`, but not on the stanzas: those are
/// authenticated by the header MAC, so the recipient list can be re-wrapped without touching
/// the body ([`rewrap`]).
fn payload_cipher(
    raw_header: &[u8],
    aad: &[u8],
    file_key: &[u8; 32],
) -> io::Result<ChaCha20Poly1305> {
    aead(&kdf(MULTI_KDF_LABEL, &raw_header[..8], aad, file_key))
}

/// Find the stanza for `secret` and recover the file key; then check the header MAC.
fn unwrap_file_key(
    secret: &SecretKey,
    aad: &[u8],
    header: &MultiStreamHeader,
    raw: &[u8],
) -> io::Result<Zeroizing<[u8; 32]>> {
    let AlgorithmId::Kem(kem) = secret.algorithm() else {
        return Err(invalid_input(Error::AlgorithmMismatch));
    };
    let unauthenticated = &raw[..raw.len() - HEADER_MAC_LEN];
    // Stanzas carry no recipient identifier: try each one of our KEM.
    for stanza in header.recipients.iter().filter(|s| s.kem == kem) {
        let Ok(ss) = registry::kem(kem).and_then(|k| k.decapsulate(secret, &stanza.kem_ciphertext))
        else {
            continue;
        };
        let Ok(opened) = wrap_key(kem, &stanza.kem_ciphertext, ss.expose())?
            .decrypt(&Nonce::default(), &stanza.wrapped_key[..])
        else {
            continue;
        };
        let opened = Zeroizing::new(opened);
        let mut file_key = Zeroizing::new([0u8; 32]);
        file_key.copy_from_slice(&opened);
        // A stanza that unwraps but fails the MAC means a malformed or malicious header (for
        // example different file keys for different recipients): reject, do not keep trying.
        let expected = header_mac(unauthenticated, aad, &file_key);
        if !bool::from(expected.ct_eq(&header.mac)) {
            return Err(decryption_failed());
        }
        return Ok(file_key);
    }
    Err(decryption_failed())
}

#[derive(PartialEq, Eq)]
enum State {
    Reading,
    Done,
    Failed,
}

/// Decrypts a stream. Implements [`Read`]; see the module documentation for the
/// "discard on error" rule.
pub struct Decryptor<R: Read> {
    inner: R,
    opener: ChunkOpener,
    inbuf: Vec<u8>,
    lookahead: Option<u8>,
    out: Zeroizing<Vec<u8>>,
    pos: usize,
    state: State,
}

impl<R: Read> Decryptor<R> {
    /// Read the header and prepare to decrypt. Fails for a key of the wrong algorithm, a
    /// malformed header or a failed decapsulation.
    pub fn new(secret: &SecretKey, aad: &[u8], mut inner: R) -> io::Result<Self> {
        let (header, raw) = AnyStreamHeader::read_from(&mut inner)?;
        let opener = ChunkOpener::start(secret, aad, &header, &raw)?;
        let chunk_ct = opener.chunk_ct;
        Ok(Self {
            inner,
            opener,
            inbuf: Vec::with_capacity(chunk_ct),
            lookahead: None,
            out: Zeroizing::new(Vec::new()),
            pos: 0,
            state: State::Reading,
        })
    }

    /// Read until `inbuf` holds a full encrypted chunk or the input ends.
    fn fill(&mut self) -> io::Result<()> {
        let mut tmp = [0u8; 8192];
        while self.inbuf.len() < self.opener.chunk_ct {
            let want = (self.opener.chunk_ct - self.inbuf.len()).min(tmp.len());
            match self.inner.read(&mut tmp[..want]) {
                Ok(0) => break,
                Ok(n) => self.inbuf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn at_eof(&mut self) -> io::Result<bool> {
        let mut b = [0u8; 1];
        loop {
            match self.inner.read(&mut b) {
                Ok(0) => return Ok(true),
                Ok(_) => {
                    self.lookahead = Some(b[0]);
                    return Ok(false);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn next_chunk(&mut self) -> io::Result<()> {
        self.inbuf.clear();
        if let Some(b) = self.lookahead.take() {
            self.inbuf.push(b);
        }
        self.fill()?;
        // The final chunk is recognised only by the end of input.
        let last = self.inbuf.len() < self.opener.chunk_ct || self.at_eof()?;
        let pt = self.opener.open(&self.inbuf, last)?;
        self.out.zeroize();
        self.out = Zeroizing::new(pt);
        self.pos = 0;
        if last {
            self.state = State::Done;
        }
        Ok(())
    }
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.out.len() {
                let n = (self.out.len() - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            match self.state {
                State::Done => return Ok(0),
                State::Failed => return Err(decryption_failed()),
                State::Reading => {
                    if let Err(e) = self.next_chunk() {
                        self.state = State::Failed;
                        self.out.zeroize();
                        return Err(e);
                    }
                }
            }
        }
    }
}

/// Push-style decryption for callers that receive data in pieces (async code, browsers,
/// network callbacks). Feed bytes with [`PushDecryptor::update`]; call
/// [`PushDecryptor::finish`] at end of input, which verifies the final chunk. As with
/// [`Decryptor`], plaintext returned before `finish` succeeds must be discarded on error.
pub struct PushDecryptor {
    secret: SecretKey,
    aad: Zeroizing<Vec<u8>>,
    buf: Vec<u8>,
    opener: Option<ChunkOpener>,
    failed: bool,
}

impl PushDecryptor {
    /// Prepare to decrypt a stream for `secret` with context `aad`.
    pub fn new(secret: &SecretKey, aad: &[u8]) -> Self {
        Self {
            secret: secret.clone(),
            aad: Zeroizing::new(aad.to_vec()),
            buf: Vec::new(),
            opener: None,
            failed: false,
        }
    }

    fn fail(&mut self, e: io::Error) -> io::Error {
        self.failed = true;
        self.buf.clear();
        e
    }

    /// Feed more ciphertext. Returns the plaintext of every chunk that is now known not to be
    /// the last one.
    pub fn update(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        if self.failed {
            return Err(decryption_failed());
        }
        self.buf.extend_from_slice(data);
        if self.opener.is_none() {
            let header_len = match AnyStreamHeader::scan(&self.buf) {
                Ok(HeaderScan::Complete(n)) => n,
                Ok(HeaderScan::NeedAtLeast(_)) => return Ok(Vec::new()),
                Err(e) => {
                    return Err(self.fail(io::Error::new(io::ErrorKind::InvalidData, e)));
                }
            };
            let raw = &self.buf[..header_len];
            let started = AnyStreamHeader::parse(raw)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .and_then(|header| ChunkOpener::start(&self.secret, &self.aad, &header, raw));
            match started {
                Ok(o) => self.opener = Some(o),
                Err(e) => return Err(self.fail(e)),
            }
            self.buf.drain(..header_len);
        }
        let mut out = Vec::new();
        let opener = self.opener.as_mut().expect("started above");
        let chunk_ct = opener.chunk_ct;
        // A full chunk is non-final only once at least one more byte has arrived.
        while self.buf.len() > chunk_ct {
            match opener.open(&self.buf[..chunk_ct], false) {
                Ok(pt) => out.extend_from_slice(&pt),
                Err(e) => {
                    out.zeroize();
                    return Err(self.fail(e));
                }
            }
            self.buf.drain(..chunk_ct);
        }
        Ok(out)
    }

    /// Signal end of input: verifies and returns the final chunk.
    pub fn finish(mut self) -> io::Result<Vec<u8>> {
        if self.failed {
            return Err(decryption_failed());
        }
        let buf = std::mem::take(&mut self.buf);
        match self.opener.as_mut() {
            None => Err(decryption_failed()), // header never completed
            Some(o) => o.open(&buf, true),
        }
    }
}

/// Encrypt everything from `input` into `output`. Returns the number of plaintext bytes.
pub fn seal_stream<R: Read, W: Write>(
    recipient: &PublicKey,
    aad: &[u8],
    mut input: R,
    output: W,
) -> io::Result<u64> {
    let mut enc = Encryptor::new(recipient, aad, output)?;
    let n = io::copy(&mut input, &mut enc)?;
    enc.finish()?.flush()?;
    Ok(n)
}

/// [`seal_stream`] for several recipients (see [`Encryptor::to_recipients`]).
pub fn seal_stream_multi<R: Read, W: Write>(
    recipients: &[&PublicKey],
    aad: &[u8],
    mut input: R,
    output: W,
) -> io::Result<u64> {
    let mut enc = Encryptor::to_recipients(recipients, aad, output, StreamOptions::default())?;
    let n = io::copy(&mut input, &mut enc)?;
    enc.finish()?.flush()?;
    Ok(n)
}

/// Decrypt everything from `input` into `output`. Returns the number of plaintext bytes.
///
/// On error, `output` may already contain plaintext of a stream that later failed
/// verification: discard it. Prefer [`decrypt_file`] for files.
pub fn open_stream<R: Read, W: Write>(
    secret: &SecretKey,
    aad: &[u8],
    input: R,
    mut output: W,
) -> io::Result<u64> {
    let mut dec = Decryptor::new(secret, aad, input)?;
    let n = io::copy(&mut dec, &mut output)?;
    output.flush()?;
    Ok(n)
}

/// A temporary file next to `target`, removed on drop unless committed.
struct TempOutput {
    path: PathBuf,
    target: PathBuf,
    file: Option<fs::File>,
}

impl TempOutput {
    fn create(target: &Path) -> io::Result<Self> {
        let dir = match target.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let name = target.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "output path has no file name")
        })?;
        let rnd: [u8; 8] = OsRng.array().map_err(invalid_input)?;
        let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let path = dir.join(format!(".{}.{suffix}.vpqc-tmp", name.to_string_lossy()));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;
        Ok(Self {
            path,
            target: target.to_path_buf(),
            file: Some(file),
        })
    }

    fn commit(mut self) -> io::Result<()> {
        let file = self.file.take().expect("file present until commit");
        file.sync_all()?;
        drop(file);
        fs::rename(&self.path, &self.target)
    }
}

impl Drop for TempOutput {
    fn drop(&mut self) {
        if self.file.is_some() {
            self.file = None;
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Encrypt everything from `input` into the file `output` (replaced atomically).
/// Returns plaintext bytes.
pub fn encrypt_to_file<R: Read>(
    recipient: &PublicKey,
    aad: &[u8],
    input: R,
    output: &Path,
) -> io::Result<u64> {
    let tmp = TempOutput::create(output)?;
    let sink = io::BufWriter::with_capacity(1 << 16, tmp.file.as_ref().expect("open"));
    let n = seal_stream(recipient, aad, input, sink)?;
    tmp.commit()?;
    Ok(n)
}

/// [`encrypt_to_file`] for several recipients.
pub fn encrypt_to_file_multi<R: Read>(
    recipients: &[&PublicKey],
    aad: &[u8],
    input: R,
    output: &Path,
) -> io::Result<u64> {
    let tmp = TempOutput::create(output)?;
    let sink = io::BufWriter::with_capacity(1 << 16, tmp.file.as_ref().expect("open"));
    let n = seal_stream_multi(recipients, aad, input, sink)?;
    tmp.commit()?;
    Ok(n)
}

/// [`encrypt_file`] for several recipients: any of them can decrypt with
/// [`decrypt_file`].
pub fn encrypt_file_multi(
    recipients: &[&PublicKey],
    aad: &[u8],
    input: &Path,
    output: &Path,
) -> io::Result<u64> {
    encrypt_to_file_multi(
        recipients,
        aad,
        io::BufReader::with_capacity(1 << 16, fs::File::open(input)?),
        output,
    )
}

/// Change the recipients of a multi-recipient stream without re-encrypting its body (ADR-0009):
/// `secret` must be one of the current recipients; the output is readable by exactly
/// `recipients`. Copies the body unchanged and returns the number of body bytes.
///
/// Removing a recipient this way does not revoke what they may already have: anyone who could
/// decrypt the old file knows its file key. Re-encrypt the data to revoke access to it.
/// Single-recipient streams (kind 5) have no file key to re-wrap: re-encrypt them.
pub fn rewrap<R: Read, W: Write>(
    secret: &SecretKey,
    aad: &[u8],
    recipients: &[&PublicKey],
    mut input: R,
    mut output: W,
) -> io::Result<u64> {
    check_recipients(recipients)?;
    let (header, raw) = AnyStreamHeader::read_from(&mut input)?;
    let AnyStreamHeader::Multi(h) = header else {
        return Err(invalid_input(Error::Format(
            "single-recipient stream: it cannot be re-wrapped, re-encrypt it",
        )));
    };
    let file_key = unwrap_file_key(secret, aad, &h, &raw)?;
    let keys = vec![*file_key; recipients.len()];
    let new_header = multi_header(recipients, &keys, &file_key, aad, h.chunk_log, &mut OsRng);
    keys.into_iter().for_each(|mut k| k.zeroize());
    output.write_all(&new_header?)?;
    let n = io::copy(&mut input, &mut output)?;
    output.flush()?;
    Ok(n)
}

/// [`rewrap`] from file to file; the output is replaced atomically.
pub fn rewrap_file(
    secret: &SecretKey,
    aad: &[u8],
    recipients: &[&PublicKey],
    input: &Path,
    output: &Path,
) -> io::Result<u64> {
    let tmp = TempOutput::create(output)?;
    let sink = io::BufWriter::with_capacity(1 << 16, tmp.file.as_ref().expect("open"));
    let source = io::BufReader::with_capacity(1 << 16, fs::File::open(input)?);
    let n = rewrap(secret, aad, recipients, source, sink)?;
    tmp.commit()?;
    Ok(n)
}

/// Decrypt everything from `input` into the file `output`. The file appears (atomically,
/// mode 0600 on Unix) only if the whole stream verifies; otherwise nothing is left behind and
/// an existing `output` is untouched.
pub fn decrypt_to_file<R: Read>(
    secret: &SecretKey,
    aad: &[u8],
    input: R,
    output: &Path,
) -> io::Result<u64> {
    let tmp = TempOutput::create(output)?;
    let sink = io::BufWriter::with_capacity(1 << 16, tmp.file.as_ref().expect("open"));
    let n = open_stream(secret, aad, input, sink)?;
    tmp.commit()?;
    Ok(n)
}

/// Encrypt the file `input` to `output` (replaced atomically). Returns plaintext bytes.
pub fn encrypt_file(
    recipient: &PublicKey,
    aad: &[u8],
    input: &Path,
    output: &Path,
) -> io::Result<u64> {
    encrypt_to_file(
        recipient,
        aad,
        io::BufReader::with_capacity(1 << 16, fs::File::open(input)?),
        output,
    )
}

/// Decrypt the file `input` to `output`; see [`decrypt_to_file`].
pub fn decrypt_file(
    secret: &SecretKey,
    aad: &[u8],
    input: &Path,
    output: &Path,
) -> io::Result<u64> {
    decrypt_to_file(
        secret,
        aad,
        io::BufReader::with_capacity(1 << 16, fs::File::open(input)?),
        output,
    )
}
