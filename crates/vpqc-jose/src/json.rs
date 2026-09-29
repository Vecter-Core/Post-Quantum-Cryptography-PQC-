//! JSON object parsing that rejects duplicate member names (RFC 7515 section 4 and RFC 7519
//! section 4: a JOSE header or claims set with duplicates MUST be rejected or handled
//! unambiguously; rejecting avoids parser-differential attacks).

use std::fmt;

use serde::Deserializer;
use serde::de::{self, MapAccess, Visitor};
use serde_json::{Map, Value};

use crate::{Error, Result};

struct StrictObject(Map<String, Value>);

impl<'de> de::Deserialize<'de> for StrictObject {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StrictObject;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut m: A,
            ) -> std::result::Result<StrictObject, A::Error> {
                let mut out = Map::new();
                while let Some((k, v)) = m.next_entry::<String, Value>()? {
                    if out.contains_key(&k) {
                        return Err(de::Error::custom("duplicate member"));
                    }
                    out.insert(k, v);
                }
                Ok(StrictObject(out))
            }
        }
        d.deserialize_map(V)
    }
}

/// Parse `bytes` as a JSON object with unique member names (nested values are not checked:
/// only top-level members have meaning here).
pub(crate) fn object(bytes: &[u8], what: &'static str) -> Result<Map<String, Value>> {
    serde_json::from_slice::<StrictObject>(bytes)
        .map(|o| o.0)
        .map_err(|_| Error::Malformed(what))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicates_and_non_objects() {
        assert!(object(br#"{"a":1,"b":2}"#, "x").is_ok());
        assert!(object(br#"{"a":1,"a":2}"#, "x").is_err());
        assert!(object(br#"[1]"#, "x").is_err());
        assert!(object(br#"{"a":1} x"#, "x").is_err());
    }
}
