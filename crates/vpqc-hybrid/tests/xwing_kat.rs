//! Known-answer tests against the official X-Wing test vectors
//! (draft-connolly-cfrg-xwing-kem, `spec/test-vectors.txt`).

use std::collections::HashMap;
use vpqc_hybrid::xwing;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Parse the vector file into a list of `field -> bytes` maps.
fn vectors() -> Vec<HashMap<String, Vec<u8>>> {
    let text = include_str!("data/xwing-test-vectors.txt");
    let mut out: Vec<HashMap<String, Vec<u8>>> = Vec::new();
    let mut current: Option<(String, String)> = None;
    let flush = |cur: &mut Option<(String, String)>, out: &mut Vec<HashMap<String, Vec<u8>>>| {
        if let Some((name, hex)) = cur.take() {
            if name == "seed" {
                out.push(HashMap::new());
            }
            out.last_mut().unwrap().insert(name, unhex(&hex));
        }
    };
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with(' ') {
            current.as_mut().unwrap().1.push_str(line.trim());
        } else {
            flush(&mut current, &mut out);
            let mut it = line.splitn(2, char::is_whitespace);
            let name = it.next().unwrap().to_string();
            let rest = it.next().unwrap_or("").trim().to_string();
            current = Some((name, rest));
        }
    }
    flush(&mut current, &mut out);
    out
}

#[test]
fn official_vectors() {
    let vs = vectors();
    assert_eq!(vs.len(), 3, "expected three official vectors");
    for v in &vs {
        let seed: [u8; 32] = v["seed"].as_slice().try_into().unwrap();
        assert_eq!(v["sk"], v["seed"]);
        assert_eq!(v["pk"].len(), xwing::PUBLIC_KEY_LEN);
        assert_eq!(v["ct"].len(), xwing::CIPHERTEXT_LEN);

        // Key generation.
        let pk = xwing::public_key_from_secret(&seed);
        assert_eq!(pk.as_slice(), v["pk"].as_slice(), "public key mismatch");

        // Encapsulation (derandomized).
        let eseed: [u8; 64] = v["eseed"].as_slice().try_into().unwrap();
        let (ct, ss) = xwing::encapsulate_derand(&v["pk"], &eseed).unwrap();
        assert_eq!(ct, v["ct"], "ciphertext mismatch");
        assert_eq!(
            ss.as_slice(),
            v["ss"].as_slice(),
            "encapsulated shared secret mismatch"
        );

        // Decapsulation.
        let ss = xwing::decapsulate_raw(&seed, &v["ct"]).unwrap();
        assert_eq!(
            ss.as_slice(),
            v["ss"].as_slice(),
            "decapsulated shared secret mismatch"
        );
    }
}
