//! A small, strict CBOR (RFC 8949) codec for the subset COSE and CWT use.
//!
//! Encoding is deterministic (RFC 8949 section 4.2.1: preferred integer and length encodings,
//! definite lengths; map keys are written in the order given, callers pass them sorted).
//! Decoding is strict so that one message has one reading:
//! * only definite lengths, only preferred (shortest) integer and length encodings;
//! * map keys are integers or strings, without duplicates; text must be UTF-8;
//! * simple values `false`, `true` and `null` only (floats are accepted, for CWT times);
//! * nesting depth at most [`MAX_DEPTH`], no trailing bytes;
//! * lengths are checked against the remaining input before anything is allocated.

use crate::{Error, Result};

/// Maximum nesting of arrays, maps and tags accepted by [`decode`].
pub const MAX_DEPTH: usize = 16;

/// A CBOR data item.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// Unsigned integer (major type 0).
    Uint(u64),
    /// Negative integer `-1 - n` (major type 1), stored as `n`.
    Nint(u64),
    /// Byte string.
    Bytes(Vec<u8>),
    /// Text string.
    Text(String),
    /// Array.
    Array(Vec<Value>),
    /// Map, in encoding order.
    Map(Vec<(Value, Value)>),
    /// Tagged item.
    Tag(u64, Box<Value>),
    /// `false` / `true`.
    Bool(bool),
    /// `null`.
    Null,
    /// Floating-point number (decoded only; never produced by this crate).
    Float(f64),
}

impl Value {
    /// An integer value.
    pub fn int(i: i64) -> Value {
        if i >= 0 {
            Value::Uint(i as u64)
        } else {
            Value::Nint(!(i as u64))
        }
    }

    /// The value as an `i64`, if it is an integer in range.
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Value::Uint(n) => i64::try_from(n).ok(),
            Value::Nint(n) => i64::try_from(n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    /// The bytes of a byte string.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The text of a text string.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// Look up an integer key in a map.
    pub fn get(&self, key: i64) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| k.as_i64() == Some(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

/// Encode a value (deterministically; floats are written as 64-bit).
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(&mut out, value);
    out
}

fn encode_into(out: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Uint(n) => head(out, 0, *n),
        Value::Nint(n) => head(out, 1, *n),
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            head(out, 4, items.len() as u64);
            for item in items {
                encode_into(out, item);
            }
        }
        Value::Map(entries) => {
            head(out, 5, entries.len() as u64);
            for (k, v) in entries {
                encode_into(out, k);
                encode_into(out, v);
            }
        }
        Value::Tag(tag, inner) => {
            head(out, 6, *tag);
            encode_into(out, inner);
        }
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Null => out.push(0xf6),
        Value::Float(f) => {
            out.push(0xfb);
            out.extend_from_slice(&f.to_be_bytes());
        }
    }
}

/// Decode exactly one data item; trailing bytes are an error.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let mut r = Reader { bytes, pos: 0 };
    let value = r.item(0)?;
    if r.pos != bytes.len() {
        return Err(Error::Malformed("trailing bytes after CBOR item"));
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

const BAD: Error = Error::Malformed("CBOR encoding");

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.pos.checked_add(n).ok_or(BAD)?;
        let s = self.bytes.get(self.pos..end).ok_or(BAD)?;
        self.pos = end;
        Ok(s)
    }

    /// The argument of a head, rejecting indefinite lengths and non-preferred encodings.
    fn argument(&mut self, info: u8) -> Result<u64> {
        let (n, min) = match info {
            0..=23 => return Ok(info as u64),
            24 => (self.take(1)?[0] as u64, 24),
            25 => (
                u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
                0x100,
            ),
            26 => (
                u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
                0x1_0000,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
                0x1_0000_0000,
            ),
            _ => return Err(Error::Malformed("indefinite or reserved CBOR length")),
        };
        if n < min {
            return Err(Error::Malformed("non-preferred CBOR integer encoding"));
        }
        Ok(n)
    }

    /// A length that fits in the remaining input (each element needs at least one byte).
    fn length(&mut self, info: u8) -> Result<usize> {
        let n = self.argument(info)?;
        let remaining = (self.bytes.len() - self.pos) as u64;
        if n > remaining {
            return Err(BAD);
        }
        Ok(n as usize)
    }

    fn item(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(Error::Malformed("CBOR nesting too deep"));
        }
        let initial = self.take(1)?[0];
        let (major, info) = (initial >> 5, initial & 0x1f);
        Ok(match major {
            0 => Value::Uint(self.argument(info)?),
            1 => Value::Nint(self.argument(info)?),
            2 => {
                let n = self.length(info)?;
                Value::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.length(info)?;
                let text = std::str::from_utf8(self.take(n)?)
                    .map_err(|_| Error::Malformed("CBOR text is not UTF-8"))?;
                Value::Text(text.to_owned())
            }
            4 => {
                let n = self.length(info)?;
                // Capacity capped: nested headers can each claim the whole remaining input.
                let mut items = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    items.push(self.item(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let n = self.length(info)?;
                let mut entries: Vec<(Value, Value)> = Vec::with_capacity(n.min(64));
                // Keys are compared by encoding, which is unique for integers and strings
                // under the preferred-encoding rule: linear time, not quadratic.
                let mut seen = std::collections::HashSet::with_capacity(n.min(64));
                let input = self.bytes;
                for _ in 0..n {
                    let start = self.pos;
                    let k = self.item(depth + 1)?;
                    if !matches!(
                        k,
                        Value::Uint(_) | Value::Nint(_) | Value::Text(_) | Value::Bytes(_)
                    ) {
                        return Err(Error::Malformed("CBOR map key type"));
                    }
                    if !seen.insert(&input[start..self.pos]) {
                        return Err(Error::Malformed("duplicate CBOR map key"));
                    }
                    let v = self.item(depth + 1)?;
                    entries.push((k, v));
                }
                Value::Map(entries)
            }
            6 => {
                let tag = self.argument(info)?;
                Value::Tag(tag, Box::new(self.item(depth + 1)?))
            }
            _ => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                25 => Value::Float(half_to_f64(u16::from_be_bytes(
                    self.take(2)?.try_into().unwrap(),
                ))),
                26 => Value::Float(f32::from_be_bytes(self.take(4)?.try_into().unwrap()) as f64),
                27 => Value::Float(f64::from_be_bytes(self.take(8)?.try_into().unwrap())),
                _ => return Err(Error::Malformed("unsupported CBOR simple value")),
            },
        })
    }
}

/// IEEE 754 binary16 to f64 (RFC 8949 appendix D).
/// Exact power of two (`powi` is not guaranteed exact on every platform).
fn pow2(k: i32) -> f64 {
    debug_assert!((-1022..=1023).contains(&k));
    f64::from_bits(((1023 + k) as u64) << 52)
}

fn half_to_f64(h: u16) -> f64 {
    let exp = (h >> 10) & 0x1f;
    let mant = (h & 0x3ff) as f64;
    let magnitude = match exp {
        0 => mant * pow2(-24),
        31 => {
            if mant == 0.0 {
                f64::INFINITY
            } else {
                f64::NAN
            }
        }
        _ => (mant + 1024.0) * pow2(exp as i32 - 25),
    };
    if h & 0x8000 != 0 {
        -magnitude
    } else {
        magnitude
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8949_appendix_a_examples() {
        let cases: Vec<(&str, Value)> = vec![
            ("00", Value::Uint(0)),
            ("17", Value::Uint(23)),
            ("1818", Value::Uint(24)),
            ("1903e8", Value::Uint(1000)),
            ("1b000000e8d4a51000", Value::Uint(1_000_000_000_000)),
            ("20", Value::int(-1)),
            ("3903e7", Value::int(-1000)),
            ("3bffffffffffffffff", Value::Nint(u64::MAX)),
            ("40", Value::Bytes(vec![])),
            ("4401020304", Value::Bytes(vec![1, 2, 3, 4])),
            ("6449455446", Value::Text("IETF".into())),
            ("62c3bc", Value::Text("\u{fc}".into())),
            (
                "83010203",
                Value::Array(vec![Value::Uint(1), Value::Uint(2), Value::Uint(3)]),
            ),
            (
                "a201020304",
                Value::Map(vec![
                    (Value::Uint(1), Value::Uint(2)),
                    (Value::Uint(3), Value::Uint(4)),
                ]),
            ),
            (
                "c11a514b67b0",
                Value::Tag(1, Box::new(Value::Uint(1_363_896_240))),
            ),
            ("f4", Value::Bool(false)),
            ("f5", Value::Bool(true)),
            ("f6", Value::Null),
        ];
        for (h, v) in cases {
            assert_eq!(decode(&hex(h)).unwrap(), v, "{h}");
            assert_eq!(encode(&v), hex(h), "{h}");
        }
        assert_eq!(decode(&hex("f93c00")).unwrap(), Value::Float(1.0));
        assert_eq!(decode(&hex("f9c400")).unwrap(), Value::Float(-4.0));
        assert_eq!(decode(&hex("fa47c35000")).unwrap(), Value::Float(100000.0));
        assert_eq!(
            decode(&hex("fb3ff199999999999a")).unwrap(),
            Value::Float(1.1)
        );
        assert_eq!(Value::int(i64::MIN).as_i64(), Some(i64::MIN));
        assert_eq!(Value::Nint(u64::MAX).as_i64(), None);
    }

    #[test]
    fn strictness() {
        for (h, why) in [
            ("1817", "non-preferred"),
            ("190017", "non-preferred"),
            ("5f4101ff", "indefinite bytes"),
            ("9fff", "indefinite array"),
            ("a201020103", "duplicate key"),
            ("a1f400", "bool key"),
            ("a18100", "array key"),
            ("a20102", "truncated"),
            ("0000", "trailing"),
            ("62c3", "truncated text"),
            ("62c328", "invalid UTF-8"),
            ("f7", "undefined"),
            ("e0", "simple 0"),
            ("f820", "simple 32"),
            ("5bffffffffffffffff", "huge length"),
            ("9bffffffffffffffff", "huge array"),
            ("1c", "reserved info"),
            ("", "empty"),
        ] {
            assert!(decode(&hex(h)).is_err(), "{why}: {h}");
        }
        let deep = "81".repeat(MAX_DEPTH + 1) + "00";
        assert!(decode(&hex(&deep)).is_err());
        let ok = "81".repeat(MAX_DEPTH) + "00";
        assert!(decode(&hex(&ok)).is_ok());
    }
}
