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

fn profile(name: &str) -> PyResult<Profile> {
    Profile::from_name(name).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "unknown profile {name:?}; expected one of: standard, fast-auth, cnsa2"
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
