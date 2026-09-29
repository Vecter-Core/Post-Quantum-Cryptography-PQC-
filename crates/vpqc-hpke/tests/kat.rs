//! Known-answer tests against the official draft-ietf-hpke-pq vectors.

use serde_json::Value;
use vpqc_hpke::{Suite, derive_key_pair, setup_base_r, setup_base_s_derand};

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn official_vectors() {
    let all: Vec<Value> =
        serde_json::from_str(include_str!("data/hpke-pq-test-vectors.json")).unwrap();
    let mut ran = Vec::new();
    for v in &all {
        let id = |k: &str| v[k].as_u64().unwrap() as u16;
        let Ok(suite) = Suite::from_ids(id("kem_id"), id("kdf_id"), id("aead_id")) else {
            continue; // algorithm not implemented by vpqc
        };
        assert_eq!(v["mode"], 0);
        let name = format!(
            "{:04x}/{:04x}/{:04x}",
            id("kem_id"),
            id("kdf_id"),
            id("aead_id")
        );
        let info = unhex(&v["info"]);

        // DeriveKeyPair.
        let (sk, pk) = derive_key_pair(suite.kem, &unhex(&v["ikmR"])).unwrap();
        assert_eq!(sk.as_slice(), unhex(&v["skRm"]), "{name}: skR");
        assert_eq!(pk, unhex(&v["pkRm"]), "{name}: pkR");

        // Deterministic encapsulation and sender key schedule.
        let (enc, ss, mut sender) =
            setup_base_s_derand(suite, &pk, &info, &unhex(&v["ikmE"])).unwrap();
        assert_eq!(enc, unhex(&v["enc"]), "{name}: enc");
        assert_eq!(
            ss.as_slice(),
            unhex(&v["shared_secret"]),
            "{name}: shared_secret"
        );
        let (key, nonce, exp) = sender.secrets_for_testing();
        assert_eq!(key, unhex(&v["key"]), "{name}: key");
        assert_eq!(nonce, unhex(&v["base_nonce"]), "{name}: base_nonce");
        assert_eq!(exp, unhex(&v["exporter_secret"]), "{name}: exporter_secret");

        // Recipient derives the same context.
        let mut recipient = setup_base_r(suite, &enc, &sk, &info).unwrap();

        // Encryptions are in sequence order.
        for (i, e) in v["encryptions"].as_array().unwrap().iter().enumerate() {
            let (aad, pt, ct) = (unhex(&e["aad"]), unhex(&e["pt"]), unhex(&e["ct"]));
            assert_eq!(
                sender.seal(&aad, &pt).unwrap(),
                ct,
                "{name}: encryption {i}"
            );
            assert_eq!(
                recipient.open(&aad, &ct).unwrap(),
                pt,
                "{name}: decryption {i}"
            );
        }

        for (i, x) in v["exports"].as_array().unwrap().iter().enumerate() {
            let out = recipient
                .export(
                    &unhex(&x["exporter_context"]),
                    x["L"].as_u64().unwrap() as usize,
                )
                .unwrap();
            assert_eq!(
                out.as_slice(),
                unhex(&x["exported_value"]),
                "{name}: export {i}"
            );
        }
        ran.push(name);
    }
    ran.sort();
    assert_eq!(
        ran,
        [
            "0041/0001/0001",
            "0042/0002/0002",
            "0051/0002/0002",
            "647a/0001/0003",
            "647a/0011/0003"
        ],
        "set of executed vectors changed"
    );
}
