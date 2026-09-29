//! Official NIST ACVP vectors (see tests/data/acvp/README.md for provenance and scope).

use serde_json::Value;
use vpqc_backend_libcrux::{mldsa, mlkem};

fn load(name: &str) -> Value {
    let path = format!("{}/tests/data/acvp/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn groups(doc: &Value) -> &Vec<Value> {
    doc["testGroups"].as_array().unwrap()
}

fn kem_level(g: &Value) -> mlkem::Level {
    match g["parameterSet"].as_str().unwrap() {
        "ML-KEM-768" => mlkem::Level::L768,
        "ML-KEM-1024" => mlkem::Level::L1024,
        other => panic!("unexpected {other}"),
    }
}

fn dsa_level(g: &Value) -> mldsa::Level {
    match g["parameterSet"].as_str().unwrap() {
        "ML-DSA-65" => mldsa::Level::L65,
        "ML-DSA-87" => mldsa::Level::L87,
        other => panic!("unexpected {other}"),
    }
}

fn passed(t: &Value) -> bool {
    match &t["testPassed"] {
        Value::Bool(b) => *b,
        Value::String(s) => s.eq_ignore_ascii_case("true"),
        _ => panic!("testPassed missing"),
    }
}

#[test]
fn ml_kem_keygen() {
    let mut n = 0;
    for g in groups(&load("ML-KEM-keyGen-FIPS203")) {
        let level = kem_level(g);
        for t in g["tests"].as_array().unwrap() {
            let mut seed = [0u8; 64];
            seed[..32].copy_from_slice(&hex(&t["d"]));
            seed[32..].copy_from_slice(&hex(&t["z"]));
            let kp = mlkem::keygen(level, &seed);
            assert_eq!(kp.public, hex(&t["ek"]), "tcId {}", t["tcId"]);
            assert_eq!(*kp.decapsulation_key, hex(&t["dk"]), "tcId {}", t["tcId"]);
            n += 1;
        }
    }
    assert_eq!(n, 50);
}

#[test]
fn ml_kem_encap_decap_and_key_checks() {
    let (mut enc, mut dec, mut ekc) = (0, 0, 0);
    for g in groups(&load("ML-KEM-encapDecap-FIPS203")) {
        let level = kem_level(g);
        for t in g["tests"].as_array().unwrap() {
            let id = &t["tcId"];
            match g["function"].as_str().unwrap() {
                "encapsulation" => {
                    let m: [u8; 32] = hex(&t["m"]).try_into().unwrap();
                    let (c, k) = mlkem::encapsulate(level, &hex(&t["ek"]), &m).unwrap();
                    assert_eq!(c, hex(&t["c"]), "tcId {id}");
                    assert_eq!(k.to_vec(), hex(&t["k"]), "tcId {id}");
                    enc += 1;
                }
                "decapsulation" => {
                    // Includes modified ciphertexts: implicit rejection must give the listed k.
                    let k = mlkem::decapsulate(level, &hex(&t["dk"]), &hex(&t["c"])).unwrap();
                    assert_eq!(k.to_vec(), hex(&t["k"]), "tcId {id} ({})", t["reason"]);
                    dec += 1;
                }
                "encapsulationKeyCheck" => {
                    let ok = mlkem::encapsulate(level, &hex(&t["ek"]), &[0u8; 32]).is_ok();
                    assert_eq!(ok, passed(t), "tcId {id} ({})", t["reason"]);
                    ekc += 1;
                }
                other => panic!("unexpected function {other}"),
            }
        }
    }
    assert_eq!((enc, dec, ekc), (50, 20, 20));
}

#[test]
fn ml_dsa_keygen() {
    let mut n = 0;
    for g in groups(&load("ML-DSA-keyGen-FIPS204")) {
        let level = dsa_level(g);
        for t in g["tests"].as_array().unwrap() {
            let seed: [u8; 32] = hex(&t["seed"]).try_into().unwrap();
            let (pk, sk) = mldsa::keygen(level, &seed);
            assert_eq!(pk, hex(&t["pk"]), "tcId {}", t["tcId"]);
            assert_eq!(*sk, hex(&t["sk"]), "tcId {}", t["tcId"]);
            n += 1;
        }
    }
    assert_eq!(n, 50);
}

#[test]
fn ml_dsa_siggen_pure() {
    let (mut det, mut hedged) = (0, 0);
    for g in groups(&load("ML-DSA-sigGen-FIPS204")) {
        let level = dsa_level(g);
        let deterministic = g["deterministic"].as_bool().unwrap();
        for t in g["tests"].as_array().unwrap() {
            let rnd: [u8; 32] = if deterministic {
                [0u8; 32]
            } else {
                hex(&t["rnd"]).try_into().unwrap()
            };
            let sig = mldsa::sign(
                level,
                &hex(&t["sk"]),
                &hex(&t["message"]),
                &hex(&t["context"]),
                &rnd,
            )
            .unwrap();
            assert_eq!(sig, hex(&t["signature"]), "tcId {}", t["tcId"]);
            if deterministic { det += 1 } else { hedged += 1 }
        }
    }
    assert_eq!((det, hedged), (30, 30));
}

#[test]
fn ml_dsa_sigver_pure() {
    let (mut valid, mut invalid) = (0, 0);
    for g in groups(&load("ML-DSA-sigVer-FIPS204")) {
        let level = dsa_level(g);
        for t in g["tests"].as_array().unwrap() {
            let ok = mldsa::verify(
                level,
                &hex(&t["pk"]),
                &hex(&t["message"]),
                &hex(&t["context"]),
                &hex(&t["signature"]),
            )
            .is_ok();
            assert_eq!(ok, passed(t), "tcId {} ({})", t["tcId"], t["reason"]);
            if ok { valid += 1 } else { invalid += 1 }
        }
    }
    assert!(
        valid > 0 && invalid > 0,
        "both outcomes must be exercised ({valid}/{invalid})"
    );
    assert_eq!(valid + invalid, 30);
}
