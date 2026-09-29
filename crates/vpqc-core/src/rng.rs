use crate::{Error, Result};

/// Source of cryptographic randomness.
///
/// Production code uses [`OsRng`]. Tests can inject a deterministic source to
/// reproduce known-answer vectors.
pub trait RandomSource {
    /// Fill `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;

    /// Return `N` random bytes.
    fn array<const N: usize>(&mut self) -> Result<[u8; N]>
    where
        Self: Sized,
    {
        let mut out = [0u8; N];
        self.fill(&mut out)?;
        Ok(out)
    }
}

/// The operating system CSPRNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRng;

impl RandomSource for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        getrandom::fill(buf).map_err(|_| Error::Rng)
    }
}

/// Helpers for tests. **Not for production use.**
#[doc(hidden)]
pub mod testing {
    use super::RandomSource;
    use crate::Result;

    /// Replays a fixed byte string, then fails.
    #[derive(Debug)]
    pub struct FixedRandom {
        data: Vec<u8>,
        pos: usize,
    }

    impl FixedRandom {
        /// Create a source that yields `data` in order.
        pub fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                pos: 0,
            }
        }
    }

    impl RandomSource for FixedRandom {
        fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
            let end = self.pos + buf.len();
            if end > self.data.len() {
                return Err(crate::Error::Rng);
            }
            buf.copy_from_slice(&self.data[self.pos..end]);
            self.pos = end;
            Ok(())
        }
    }
}
