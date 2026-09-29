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
use vpqc_core::{AeadId, AlgorithmId, Error, OsRng, PublicKey, RandomSource, SecretKey};
use vpqc_format::{DEFAULT_CHUNK_LOG, StreamHeader};
use zeroize::{Zeroize, Zeroizing};

use crate::registry;

const KDF_LABEL: &[u8] = b"vpqc-stream-v1";
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

fn derive_key(header: &[u8], aad: &[u8], shared_secret: &[u8; 32]) -> io::Result<ChaCha20Poly1305> {
    let mut input = Zeroizing::new(Vec::with_capacity(
        KDF_LABEL.len() + 16 + header.len() + aad.len() + 32,
    ));
    input.extend_from_slice(KDF_LABEL);
    input.extend_from_slice(&(header.len() as u64).to_be_bytes());
    input.extend_from_slice(header);
    input.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    input.extend_from_slice(aad);
    input.extend_from_slice(shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    libcrux_sha3::shake256_ema(&mut *key, &input);
    ChaCha20Poly1305::new_from_slice(&*key)
        .map_err(|_| invalid_input(Error::Backend("bad AEAD key")))
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
        header: &StreamHeader,
        raw: &[u8],
    ) -> io::Result<Self> {
        if secret.algorithm() != AlgorithmId::Kem(header.kem) {
            return Err(invalid_input(Error::AlgorithmMismatch));
        }
        let ss = registry::kem(header.kem)
            .and_then(|k| k.decapsulate(secret, &header.kem_ciphertext))
            .map_err(|_| decryption_failed())?;
        Ok(Self {
            cipher: derive_key(raw, aad, ss.expose())?,
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
        let (header, raw) = StreamHeader::read_from(&mut inner)?;
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
            // Header: 12 fixed bytes, then the KEM ciphertext whose length is in bytes 10..12.
            if self.buf.len() < 12 {
                return Ok(Vec::new());
            }
            let header_len = 12 + u16::from_be_bytes([self.buf[10], self.buf[11]]) as usize;
            if self.buf.len() < header_len {
                return Ok(Vec::new());
            }
            let mut cursor = &self.buf[..header_len];
            let started = StreamHeader::read_from(&mut cursor).and_then(|(header, raw)| {
                ChunkOpener::start(&self.secret, &self.aad, &header, &raw)
            });
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
