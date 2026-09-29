//! A minimal DER writer: only the types a certificate needs, all definite-length.

pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;

pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes = n.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

pub(crate) fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

pub(crate) fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SET, &parts.concat())
}

/// A non-negative INTEGER from big-endian magnitude bytes.
pub(crate) fn uint(magnitude: &[u8]) -> Vec<u8> {
    let trimmed: &[u8] = match magnitude.iter().position(|b| *b != 0) {
        Some(i) => &magnitude[i..],
        None => &[0],
    };
    let mut content = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(trimmed);
    tlv(0x02, &content)
}

/// An OBJECT IDENTIFIER from its encoded content bytes.
pub(crate) fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

pub(crate) fn boolean(v: bool) -> Vec<u8> {
    tlv(0x01, &[if v { 0xff } else { 0x00 }])
}

pub(crate) fn octets(content: &[u8]) -> Vec<u8> {
    tlv(0x04, content)
}

/// BIT STRING with `unused` trailing bits in the last byte.
pub(crate) fn bits(unused: u8, content: &[u8]) -> Vec<u8> {
    let mut c = vec![unused];
    c.extend_from_slice(content);
    tlv(0x03, &c)
}

pub(crate) fn utf8(s: &str) -> Vec<u8> {
    tlv(0x0c, s.as_bytes())
}

/// Context-specific constructed tag `[n]` (EXPLICIT).
pub(crate) fn explicit(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, content)
}

/// Context-specific primitive tag `[n]` (IMPLICIT, primitive).
pub(crate) fn implicit(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | n, content)
}

/// Days since 1970-01-01 to (year, month, day) in the proleptic Gregorian calendar
/// (H. Hinnant, "chrono-compatible low-level date algorithms").
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// RFC 5280 section 4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050, always in UTC
/// with seconds.
pub(crate) fn time(unix: i64) -> Vec<u8> {
    let (y, mo, d) = civil_from_days(unix.div_euclid(86_400));
    let s = unix.rem_euclid(86_400);
    let (h, mi, se) = (s / 3600, (s % 3600) / 60, s % 60);
    if (1950..2050).contains(&y) {
        tlv(
            0x17,
            format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{se:02}Z", y % 100).as_bytes(),
        )
    } else {
        tlv(
            0x18,
            format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{se:02}Z").as_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_integers_and_times() {
        assert_eq!(tlv(0x04, &[0; 0x7f])[..2], [0x04, 0x7f]);
        assert_eq!(tlv(0x04, &[0; 0x80])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(tlv(0x04, &[0; 0x1234])[..4], [0x04, 0x82, 0x12, 0x34]);
        assert_eq!(uint(&[0, 0, 5]), [0x02, 0x01, 0x05]);
        assert_eq!(uint(&[0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(uint(&[0, 0]), [0x02, 0x01, 0x00]);
        assert_eq!(time(0), tlv(0x17, b"700101000000Z"));
        assert_eq!(time(951_782_400), tlv(0x17, b"000229000000Z")); // 2000-02-29 (leap day)
        assert_eq!(time(2_524_607_999), tlv(0x17, b"491231235959Z"));
        assert_eq!(time(2_524_608_000), tlv(0x18, b"20500101000000Z"));
        assert_eq!(time(4_102_444_800), tlv(0x18, b"21000101000000Z"));
    }
}
