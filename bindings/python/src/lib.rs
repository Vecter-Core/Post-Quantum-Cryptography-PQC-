//! Native extension for the `vpqc` Python package. Exposes byte-oriented primitives;
//! the idiomatic API (classes, type hints, exceptions) lives in `python/vpqc/`.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use vpqc::{AlgorithmId, Error, Profile, encryption, keys, signing};

/// Map a vpqc error to the matching Python exception class in `vpqc.errors`.
fn to_py(py: Python<'_>, e: Error) -> PyErr {
    let name = match e {
        Error::DecryptionFailed => "DecryptionError",
        Error::VerificationFailed => "VerificationError",
        Error::Rng | Error::Backend(_) => "BackendError",
        _ => "InvalidInputError",
    };
    match py.import("vpqc.errors").and_then(|m| m.getattr(name)) {
        Ok(cls) => match cls.call1((e.to_string(),)) {
            Ok(inst) => PyErr::from_value(inst),
            Err(err) => err,
        },
        Err(err) => err,
    }
}

/// Map a streaming `io::Error`: crypto failures to vpqc exceptions, the rest to `OSError`.
fn io_to_py(py: Python<'_>, e: std::io::Error) -> PyErr {
    match vpqc::stream::crypto_error(&e) {
        Some(c) => to_py(py, c.clone()),
        None => PyErr::from(e),
    }
}

fn profile(name: &str) -> PyResult<Profile> {
    Profile::from_name(name).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "unknown profile {name:?}; expected one of: standard, fast-auth, cnsa2, high"
        ))
    })
}

#[pymodule]
mod _vpqc {
    use super::*;

    /// Native ABI version of this extension.
    #[pymodule_export]
    const NATIVE_VERSION: &str = env!("CARGO_PKG_VERSION");

    /// Available profiles as `(name, kem, signature)` tuples.
    #[pyfunction]
    fn profiles() -> Vec<(&'static str, &'static str, &'static str)> {
        Profile::ALL
            .iter()
            .map(|p| (p.name(), p.kem().name(), p.signature().name()))
            .collect()
    }

    /// Generate an encryption key pair. Returns `(public, secret)` in binary encoding.
    #[pyfunction]
    fn generate_encryption_keypair<'py>(
        py: Python<'py>,
        profile_name: &str,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let p = profile(profile_name)?;
        let pair = py
            .detach(|| encryption::generate(p))
            .map_err(|e| to_py(py, e))?;
        Ok((
            PyBytes::new(py, &keys::public_to_bytes(&pair.public)),
            PyBytes::new(py, &keys::secret_to_bytes(&pair.secret)),
        ))
    }

    /// Generate a signing key pair. Returns `(public, secret)` in binary encoding.
    #[pyfunction]
    fn generate_signing_keypair<'py>(
        py: Python<'py>,
        profile_name: &str,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let p = profile(profile_name)?;
        let pair = py
            .detach(|| signing::generate(p))
            .map_err(|e| to_py(py, e))?;
        Ok((
            PyBytes::new(py, &keys::public_to_bytes(&pair.public)),
            PyBytes::new(py, &keys::secret_to_bytes(&pair.secret)),
        ))
    }

    /// Encrypt `plaintext` to `public_key`, authenticating `aad`.
    #[pyfunction]
    fn seal<'py>(
        py: Python<'py>,
        public_key: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let pk = keys::public_from_bytes(public_key).map_err(|e| to_py(py, e))?;
        let out = py
            .detach(|| encryption::seal(&pk, plaintext, aad))
            .map_err(|e| to_py(py, e))?;
        Ok(PyBytes::new(py, &out))
    }

    /// Decrypt a sealed message.
    #[pyfunction]
    fn unseal<'py>(
        py: Python<'py>,
        secret_key: &[u8],
        sealed: &[u8],
        aad: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let sk = keys::secret_from_bytes(secret_key).map_err(|e| to_py(py, e))?;
        let out = py
            .detach(|| encryption::open(&sk, sealed, aad))
            .map_err(|e| to_py(py, e))?;
        Ok(PyBytes::new(py, &out))
    }

    /// Sign `message` under `context`.
    #[pyfunction]
    fn sign<'py>(
        py: Python<'py>,
        secret_key: &[u8],
        message: &[u8],
        context: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let sk = keys::secret_from_bytes(secret_key).map_err(|e| to_py(py, e))?;
        let out = py
            .detach(|| signing::sign(&sk, message, context))
            .map_err(|e| to_py(py, e))?;
        Ok(PyBytes::new(py, &out))
    }

    /// Verify a detached signature; raises `VerificationError` if invalid.
    #[pyfunction]
    fn verify(
        py: Python<'_>,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> PyResult<()> {
        let pk = keys::public_from_bytes(public_key).map_err(|e| to_py(py, e))?;
        py.detach(|| signing::verify(&pk, message, context, signature))
            .map_err(|e| to_py(py, e))
    }

    /// Stream-encrypt a file (any size, constant memory). Returns plaintext bytes.
    #[pyfunction]
    fn encrypt_file(
        py: Python<'_>,
        public_keys: Vec<Vec<u8>>,
        aad: &[u8],
        input: std::path::PathBuf,
        output: std::path::PathBuf,
        envelope: bool,
    ) -> PyResult<u64> {
        let pks = parse_recipients(py, &public_keys)?;
        let refs: Vec<_> = pks.iter().collect();
        py.detach(|| match (&refs[..], envelope) {
            ([pk], false) => vpqc::stream::encrypt_file(pk, aad, &input, &output),
            _ => vpqc::stream::encrypt_file_multi(&refs, aad, &input, &output),
        })
        .map_err(|e| io_to_py(py, e))
    }

    fn parse_recipients(py: Python<'_>, public_keys: &[Vec<u8>]) -> PyResult<Vec<vpqc::PublicKey>> {
        if public_keys.is_empty() {
            return Err(to_py(py, Error::Format("at least one recipient required")));
        }
        public_keys
            .iter()
            .map(|k| keys::public_from_bytes(k).map_err(|e| to_py(py, e)))
            .collect()
    }

    /// Change the recipients of a multi-recipient file without re-encrypting it (ADR-0009).
    #[pyfunction]
    fn rewrap_file(
        py: Python<'_>,
        secret_key: &[u8],
        public_keys: Vec<Vec<u8>>,
        aad: &[u8],
        input: std::path::PathBuf,
        output: std::path::PathBuf,
    ) -> PyResult<u64> {
        let sk = keys::secret_from_bytes(secret_key).map_err(|e| to_py(py, e))?;
        let pks = parse_recipients(py, &public_keys)?;
        let refs: Vec<_> = pks.iter().collect();
        py.detach(|| vpqc::stream::rewrap_file(&sk, aad, &refs, &input, &output))
            .map_err(|e| io_to_py(py, e))
    }

    /// Decrypt a stream file; the output appears only if the whole stream verifies.
    #[pyfunction]
    fn decrypt_file(
        py: Python<'_>,
        secret_key: &[u8],
        aad: &[u8],
        input: std::path::PathBuf,
        output: std::path::PathBuf,
    ) -> PyResult<u64> {
        let sk = keys::secret_from_bytes(secret_key).map_err(|e| to_py(py, e))?;
        py.detach(|| vpqc::stream::decrypt_file(&sk, aad, &input, &output))
            .map_err(|e| io_to_py(py, e))
    }

    /// Incremental stream encryption (ADR-0007).
    #[pyclass(module = "vpqc._vpqc")]
    struct StreamEncryptor {
        inner: Option<vpqc::stream::Encryptor<Vec<u8>>>,
    }

    #[pymethods]
    impl StreamEncryptor {
        #[new]
        fn new(py: Python<'_>, public_keys: Vec<Vec<u8>>, aad: &[u8]) -> PyResult<Self> {
            let pks = parse_recipients(py, &public_keys)?;
            let refs: Vec<_> = pks.iter().collect();
            let enc = match refs[..] {
                [pk] => vpqc::stream::Encryptor::new(pk, aad, Vec::new()),
                _ => vpqc::stream::Encryptor::to_recipients(&refs, aad, Vec::new(), Default::default()),
            }
            .map_err(|e| io_to_py(py, e))?;
            Ok(Self { inner: Some(enc) })
        }

        /// Add plaintext; returns ciphertext produced so far (first call includes the header).
        fn update<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
            use std::io::Write;
            let enc = self
                .inner
                .as_mut()
                .ok_or_else(|| to_py(py, Error::Format("stream already finished")))?;
            enc.write_all(data).map_err(|e| io_to_py(py, e))?;
            Ok(PyBytes::new(py, &std::mem::take(enc.get_mut())))
        }

        /// Write the final chunk; returns the remaining ciphertext.
        fn finalize<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
            let enc = self
                .inner
                .take()
                .ok_or_else(|| to_py(py, Error::Format("stream already finished")))?;
            Ok(PyBytes::new(
                py,
                &enc.finish().map_err(|e| io_to_py(py, e))?,
            ))
        }
    }

    /// Incremental stream decryption.
    #[pyclass(module = "vpqc._vpqc")]
    struct StreamDecryptor {
        inner: Option<vpqc::stream::PushDecryptor>,
    }

    #[pymethods]
    impl StreamDecryptor {
        #[new]
        fn new(py: Python<'_>, secret_key: &[u8], aad: &[u8]) -> PyResult<Self> {
            let sk = keys::secret_from_bytes(secret_key).map_err(|e| to_py(py, e))?;
            Ok(Self {
                inner: Some(vpqc::stream::PushDecryptor::new(&sk, aad)),
            })
        }

        /// Add ciphertext; returns plaintext of the chunks that are complete.
        fn update<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
            let dec = self
                .inner
                .as_mut()
                .ok_or_else(|| to_py(py, Error::Format("stream already finished")))?;
            Ok(PyBytes::new(
                py,
                &dec.update(data).map_err(|e| io_to_py(py, e))?,
            ))
        }

        /// Verify the final chunk and return its plaintext.
        fn finalize<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
            let dec = self
                .inner
                .take()
                .ok_or_else(|| to_py(py, Error::Format("stream already finished")))?;
            Ok(PyBytes::new(
                py,
                &dec.finish().map_err(|e| io_to_py(py, e))?,
            ))
        }
    }

    /// Armored text encoding of a public key.
    #[pyfunction]
    fn public_key_to_text(py: Python<'_>, public_key: &[u8]) -> PyResult<String> {
        let pk = keys::public_from_bytes(public_key).map_err(|e| to_py(py, e))?;
        Ok(keys::public_to_text(&pk))
    }

    /// Parse an armored public key into its binary encoding.
    #[pyfunction]
    fn public_key_from_text<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyBytes>> {
        let pk = keys::public_from_text(text).map_err(|e| to_py(py, e))?;
        Ok(PyBytes::new(py, &keys::public_to_bytes(&pk)))
    }

    /// Armored text encoding of a secret key. Unencrypted.
    #[pyfunction]
    fn secret_key_to_text(py: Python<'_>, secret_key: &[u8]) -> PyResult<String> {
        let sk = keys::secret_from_bytes(secret_key).map_err(|e| to_py(py, e))?;
        Ok(keys::secret_to_text(&sk))
    }

    /// Parse an armored secret key into its binary encoding.
    #[pyfunction]
    fn secret_key_from_text<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyBytes>> {
        let sk = keys::secret_from_text(text).map_err(|e| to_py(py, e))?;
        Ok(PyBytes::new(py, &keys::secret_to_bytes(&sk)))
    }

    /// Describe an encoded key: `{"kind", "algorithm", "hybrid", "post_quantum", "size"}`.
    #[pyfunction]
    fn describe_key<'py>(py: Python<'py>, key: &[u8]) -> PyResult<Bound<'py, PyDict>> {
        let (kind, alg, size) = if let Ok(pk) = keys::public_from_bytes(key) {
            ("public", pk.algorithm(), pk.as_bytes().len())
        } else {
            let sk = keys::secret_from_bytes(key).map_err(|e| to_py(py, e))?;
            ("secret", sk.algorithm(), sk.expose_bytes().len())
        };
        let (hybrid, pq) = match alg {
            AlgorithmId::Kem(k) => (k.is_hybrid(), true),
            AlgorithmId::Sig(s) => (
                matches!(s, vpqc::SigId::Ed25519MlDsa65),
                s.is_post_quantum(),
            ),
        };
        let d = PyDict::new(py);
        d.set_item("kind", kind)?;
        d.set_item("algorithm", alg.name())?;
        d.set_item("hybrid", hybrid)?;
        d.set_item("post_quantum", pq)?;
        d.set_item("size", size)?;
        Ok(d)
    }
}
