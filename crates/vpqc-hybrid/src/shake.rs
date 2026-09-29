/// SHAKE256 (FIPS 202, libcrux) over the concatenation of `parts`, filling `out`.
pub(crate) fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    let mut input =
        zeroize::Zeroizing::new(Vec::with_capacity(parts.iter().map(|p| p.len()).sum()));
    for p in parts {
        input.extend_from_slice(p);
    }
    libcrux_sha3::shake256_ema(out, &input);
}
