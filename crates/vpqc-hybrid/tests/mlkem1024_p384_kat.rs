//! Known-answer tests against the official MLKEM1024-P384 vectors
//! (draft-irtf-cfrg-concrete-hybrid-kems, `test-vectors.md`).

use std::collections::HashMap;
use vpqc_hybrid::mlkem1024_p384 as h;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Vectors are `name = hex` with continuation lines indented; a new `seed` starts a vector.
fn vectors() -> Vec<HashMap<String, Vec<u8>>> {
    let text = include_str!("data/mlkem1024-p384-test-vectors.md");
    let mut out: Vec<HashMap<String, Vec<u8>>> = Vec::new();
    let mut cur: Option<(String, String)> = None;
    let flush = |cur: &mut Option<(String, String)>, out: &mut Vec<HashMap<String, Vec<u8>>>| {
        if let Some((name, hex)) = cur.take() {
            if name == "seed" {
                out.push(HashMap::new());
            }
            out.last_mut().unwrap().insert(name, unhex(&hex));
        }
    };
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("~~~") || t.starts_with("##") {
            continue;
        }
        if let Some((name, rest)) = t.split_once(" = ").filter(|(n, _)| {
            n.chars().all(|c| c.is_ascii_lowercase() || c == '_') && !line.starts_with(' ')
        }) {
            flush(&mut cur, &mut out);
            cur = Some((name.to_string(), rest.to_string()));
        } else if let Some((_, hex)) = cur.as_mut() {
            hex.push_str(t);
        }
    }
    flush(&mut cur, &mut out);
    out
}

#[test]
fn official_vectors() {
    let vs = vectors();
    assert_eq!(vs.len(), 10, "expected ten official vectors");
    for (i, v) in vs.iter().enumerate() {
        let seed: [u8; 32] = v["seed"].as_slice().try_into().unwrap();
        assert_eq!(v["decapsulation_key"], v["seed"], "vector {i}");
        assert_eq!(v["encapsulation_key"].len(), h::PUBLIC_KEY_LEN);
        assert_eq!(v["ciphertext"].len(), h::CIPHERTEXT_LEN);

        // DeriveKeyPair.
        let pk = h::public_key_from_secret(&seed).unwrap();
        assert_eq!(pk, v["encapsulation_key"], "vector {i}: encapsulation key");
        assert_eq!(
            h::t_component_secret(&seed).unwrap().as_slice(),
            v["decapsulation_key_t"].as_slice(),
            "vector {i}: P-384 private scalar"
        );

        // EncapsDerand.
        let rnd: [u8; h::RANDOMNESS_LEN] = v["randomness"].as_slice().try_into().unwrap();
        let (ct, ss) = h::encapsulate_derand(&v["encapsulation_key"], &rnd).unwrap();
        assert_eq!(ct, v["ciphertext"], "vector {i}: ciphertext");
        assert_eq!(
            ss.as_slice(),
            v["shared_secret"].as_slice(),
            "vector {i}: encaps shared secret"
        );

        // Decaps.
        let ss = h::decapsulate_raw(&seed, &v["ciphertext"]).unwrap();
        assert_eq!(
            ss.as_slice(),
            v["shared_secret"].as_slice(),
            "vector {i}: decaps shared secret"
        );
    }
}
