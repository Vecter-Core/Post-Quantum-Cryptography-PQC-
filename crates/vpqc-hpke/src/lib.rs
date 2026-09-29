//! HPKE (Hybrid Public Key Encryption) with post-quantum and PQ/T hybrid KEMs.
//!
//! Implements the base and PSK modes of HPKE as specified in `draft-ietf-hpke-hpke`
//! (RFC 9180bis, including single-stage KDFs) with the KEMs of `draft-ietf-hpke-pq`, and is
//! checked against that draft's official test vectors.
//!
//! | Kind | Supported |
//! |---|---|
//! | KEM | `MLKEM768-X25519` (X-Wing, `0x647a`), `MLKEM1024-P384` (`0x0051`), ML-KEM-768 (`0x0041`), ML-KEM-1024 (`0x0042`) |
//! | KDF | HKDF-SHA256/384/512 (`0x0001`..`0x0003`), SHAKE128 (`0x0010`), SHAKE256 (`0x0011`) |
//! | AEAD | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, export-only (`0xFFFF`) |
//!
//! Classical DHKEMs are intentionally not offered: they are not quantum-resistant. The
//! authenticated modes (`Auth`, `AuthPSK`) do not exist for these KEMs.
//!
//! ```
//! use vpqc_hpke::{Suite, generate_key_pair, seal, open};
//! let suite = Suite::DEFAULT; // X-Wing, HKDF-SHA256, ChaCha20-Poly1305
//! let (sk, pk) = generate_key_pair(suite.kem)?;
//! let (enc, ct) = seal(suite, &pk, b"info", b"aad", b"hello")?;
//! assert_eq!(open(suite, &enc, &sk, b"info", b"aad", &ct)?, b"hello");
//! # Ok::<(), vpqc_core::Error>(())
//! ```

mod aead;
mod kdf;
mod kem;

pub use aead::Aead;
pub use kdf::Kdf;
pub use kem::{Kem, decap, derive_key_pair, encap, encap_derand, generate_key_pair};

use vpqc_core::{Error, Result};
use zeroize::{Zeroize, Zeroizing};

/// A ciphersuite: KEM, KDF and AEAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suite {
    /// Key encapsulation mechanism.
    pub kem: Kem,
    /// Key derivation function.
    pub kdf: Kdf,
    /// Authenticated encryption.
    pub aead: Aead,
}

impl Suite {
    /// vpqc default: X-Wing, HKDF-SHA256, ChaCha20-Poly1305.
    pub const DEFAULT: Suite = Suite {
        kem: Kem::XWing,
        kdf: Kdf::HkdfSha256,
        aead: Aead::ChaCha20Poly1305,
    };
    /// High-security suite: MLKEM1024-P384, HKDF-SHA384, AES-256-GCM.
    pub const HIGH: Suite = Suite {
        kem: Kem::MlKem1024P384,
        kdf: Kdf::HkdfSha384,
        aead: Aead::Aes256Gcm,
    };

    /// Build a suite from IANA identifiers.
    pub fn from_ids(kem: u16, kdf: u16, aead: u16) -> Result<Self> {
        Ok(Suite {
            kem: Kem::from_id(kem)?,
            kdf: Kdf::from_id(kdf)?,
            aead: Aead::from_id(aead)?,
        })
    }

    /// `suite_id` for the key schedule: `"HPKE" || kem_id || kdf_id || aead_id`.
    fn suite_id(&self) -> [u8; 10] {
        let mut s = [0u8; 10];
        s[..4].copy_from_slice(b"HPKE");
        s[4..6].copy_from_slice(&self.kem.id().to_be_bytes());
        s[6..8].copy_from_slice(&self.kdf.id().to_be_bytes());
        s[8..10].copy_from_slice(&self.aead.id().to_be_bytes());
        s
    }
}

/// HPKE mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Base mode: encryption to a public key.
    Base,
    /// PSK mode: additionally authenticated by a pre-shared key.
    Psk,
}

impl Mode {
    fn byte(self) -> u8 {
        match self {
            Mode::Base => 0,
            Mode::Psk => 1,
        }
    }
}

/// An encryption context (sender or recipient), after `Setup*`.
///
/// A context must be used by one role only; the sequence number advances with every
/// successful `seal`/`open`, and nonces are never reused.
pub struct Context {
    suite: Suite,
    key: Zeroizing<Vec<u8>>,
    base_nonce: Zeroizing<Vec<u8>>,
    exporter_secret: Zeroizing<Vec<u8>>,
    seq: u64,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Context({:?}, seq {}, <secrets redacted>)",
            self.suite, self.seq
        )
    }
}

/// Encode a length as two big-endian bytes, failing if it does not fit.
fn len16(n: usize) -> Result<[u8; 2]> {
    u16::try_from(n)
        .map(u16::to_be_bytes)
        .map_err(|_| Error::Format("HPKE input too long"))
}

fn length_prefixed(x: &[u8]) -> Result<Vec<u8>> {
    let mut v = Vec::with_capacity(2 + x.len());
    v.extend_from_slice(&len16(x.len())?);
    v.extend_from_slice(x);
    Ok(v)
}

fn key_schedule(
    suite: Suite,
    mode: Mode,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<Context> {
    match mode {
        Mode::Base if !psk.is_empty() || !psk_id.is_empty() => {
            return Err(Error::Format("PSK input provided in base mode"));
        }
        Mode::Psk if psk.is_empty() || psk_id.is_empty() => {
            return Err(Error::Format("PSK mode requires psk and psk_id"));
        }
        Mode::Psk if psk.len() < 32 => {
            return Err(Error::Format("PSK must be at least 32 bytes"));
        }
        _ => {}
    }
    let sid = suite.suite_id();
    let (nk, nn, nh) = (suite.aead.nk(), suite.aead.nn(), suite.kdf.nh());

    let (key, base_nonce, exporter_secret) = if suite.kdf.is_two_stage() {
        let psk_id_hash = suite
            .kdf
            .labeled_extract(&sid, b"", b"psk_id_hash", psk_id)?;
        let info_hash = suite.kdf.labeled_extract(&sid, b"", b"info_hash", info)?;
        let mut ctx = Vec::with_capacity(1 + 2 * nh);
        ctx.push(mode.byte());
        ctx.extend_from_slice(&psk_id_hash);
        ctx.extend_from_slice(&info_hash);
        let secret = Zeroizing::new(suite.kdf.labeled_extract(
            &sid,
            shared_secret,
            b"secret",
            psk,
        )?);
        (
            suite.kdf.labeled_expand(&sid, &secret, b"key", &ctx, nk)?,
            suite
                .kdf
                .labeled_expand(&sid, &secret, b"base_nonce", &ctx, nn)?,
            suite.kdf.labeled_expand(&sid, &secret, b"exp", &ctx, nh)?,
        )
    } else {
        let mut secrets = Zeroizing::new(length_prefixed(psk)?);
        secrets.extend_from_slice(&length_prefixed(shared_secret)?);
        let mut context = vec![mode.byte()];
        context.extend_from_slice(&length_prefixed(psk_id)?);
        context.extend_from_slice(&length_prefixed(info)?);
        let mut all =
            suite
                .kdf
                .labeled_derive(&sid, &secrets, b"secret", &context, nk + nn + nh)?;
        let exp = all.split_off(nk + nn);
        let nonce = all.split_off(nk);
        (all, nonce, exp)
    };
    Ok(Context {
        suite,
        key: Zeroizing::new(key),
        base_nonce: Zeroizing::new(base_nonce),
        exporter_secret: Zeroizing::new(exporter_secret),
        seq: 0,
    })
}

impl Context {
    fn nonce(&self) -> Vec<u8> {
        let mut n = self.base_nonce.to_vec();
        let seq = self.seq.to_be_bytes();
        let off = n.len() - seq.len();
        for (a, b) in n[off..].iter_mut().zip(seq) {
            *a ^= b;
        }
        n
    }

    fn advance(&mut self) -> Result<()> {
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(Error::Format("HPKE message limit reached"))?;
        Ok(())
    }

    /// Encrypt the next message (sender side).
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.suite.aead == Aead::ExportOnly {
            return Err(Error::Unsupported("export-only suite cannot encrypt"));
        }
        let ct = self
            .suite
            .aead
            .seal(&self.key, &self.nonce(), aad, plaintext)?;
        self.advance()?;
        Ok(ct)
    }

    /// Decrypt the next message (recipient side).
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if self.suite.aead == Aead::ExportOnly {
            return Err(Error::Unsupported("export-only suite cannot decrypt"));
        }
        let pt = self
            .suite
            .aead
            .open(&self.key, &self.nonce(), aad, ciphertext)?;
        self.advance()?;
        Ok(pt)
    }

    /// Export a secret of length `len` bound to `exporter_context`.
    ///
    /// Exported values are identical for a replayed `enc`: do not use them as AEAD
    /// (key, nonce) pairs without a fresh recipient-provided nonce.
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>> {
        let sid = self.suite.suite_id();
        let out = if self.suite.kdf.is_two_stage() {
            self.suite.kdf.labeled_expand(
                &sid,
                &self.exporter_secret,
                b"sec",
                exporter_context,
                len,
            )?
        } else {
            self.suite.kdf.labeled_derive(
                &sid,
                &self.exporter_secret,
                b"sec",
                exporter_context,
                len,
            )?
        };
        Ok(Zeroizing::new(out))
    }

    /// Sequence number of the next message.
    pub fn sequence(&self) -> u64 {
        self.seq
    }

    /// Test helper: the derived key, base nonce and exporter secret.
    #[doc(hidden)]
    pub fn secrets_for_testing(&self) -> (&[u8], &[u8], &[u8]) {
        (&self.key, &self.base_nonce, &self.exporter_secret)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        self.seq.zeroize();
    }
}

/// Sender setup, base mode. Returns `(enc, context)`.
pub fn setup_base_s(suite: Suite, pk_r: &[u8], info: &[u8]) -> Result<(Vec<u8>, Context)> {
    let (ss, enc) = encap(suite.kem, pk_r)?;
    Ok((enc, key_schedule(suite, Mode::Base, &ss, info, b"", b"")?))
}

/// Deterministic sender setup (test vectors). `randomness` length is `suite.kem.n_random()`.
#[doc(hidden)]
pub fn setup_base_s_derand(
    suite: Suite,
    pk_r: &[u8],
    info: &[u8],
    randomness: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>, Context)> {
    let (ss, enc) = encap_derand(suite.kem, pk_r, randomness)?;
    let ctx = key_schedule(suite, Mode::Base, &ss, info, b"", b"")?;
    Ok((enc, ss, ctx))
}

/// Recipient setup, base mode.
pub fn setup_base_r(suite: Suite, enc: &[u8], sk_r: &[u8], info: &[u8]) -> Result<Context> {
    let ss = decap(suite.kem, enc, sk_r)?;
    key_schedule(suite, Mode::Base, &ss, info, b"", b"")
}

/// Sender setup, PSK mode (`psk` at least 32 bytes).
pub fn setup_psk_s(
    suite: Suite,
    pk_r: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<(Vec<u8>, Context)> {
    let (ss, enc) = encap(suite.kem, pk_r)?;
    Ok((enc, key_schedule(suite, Mode::Psk, &ss, info, psk, psk_id)?))
}

/// Recipient setup, PSK mode.
pub fn setup_psk_r(
    suite: Suite,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<Context> {
    let ss = decap(suite.kem, enc, sk_r)?;
    key_schedule(suite, Mode::Psk, &ss, info, psk, psk_id)
}

/// Single-shot encryption: returns `(enc, ciphertext)`.
pub fn seal(
    suite: Suite,
    pk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    if suite.aead == Aead::ExportOnly {
        return Err(Error::Unsupported("export-only suite cannot encrypt"));
    }
    let (enc, mut ctx) = setup_base_s(suite, pk_r, info)?;
    Ok((enc, ctx.seal(aad, plaintext)?))
}

/// Single-shot decryption. Any failure is reported as [`Error::DecryptionFailed`].
pub fn open(
    suite: Suite,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut ctx = setup_base_r(suite, enc, sk_r, info).map_err(|_| Error::DecryptionFailed)?;
    ctx.open(aad, ciphertext)
}
