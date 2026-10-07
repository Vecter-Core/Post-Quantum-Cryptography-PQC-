# ADR-0015: Shadow mode where there is negotiation; no global profile kill-switch

- Status: accepted
- Date: 2026-10-07

## Context
The roadmap (section 5.4) listed two migration aids:
1. a **shadow mode**: run hybrid cryptography in a recording mode, to measure cost and
   compatibility before enforcing it;
2. a **kill-switch profile flag**: change the profile of a whole system through configuration,
   with control over downgrade.

## Decision
### Shadow mode: only where a peer can say no
Shadow mode makes sense where two parties negotiate, because a peer that does not support the
new algorithms can be observed without being broken. vpqc provides it there:
- **TLS sidecar:** `vpqc-tls-proxy ... --allow-classical` uses `KxPolicy::PreferHybrid`: hybrid
  groups first, classical fallback for old peers, and every connection reports the negotiated
  group, so fallbacks can be logged and counted. Without the flag the policy is
  `RequireHybrid` and old peers fail the handshake (enforcing mode).
- **Probes:** `vpqc-tls-proxy probe` and `vpqc ssh probe` report what a server offers, with
  `--require-pq` for a CI gate; `vpqc scan` and `vpqc lint` inventory what code and
  configuration would need to change.

For **stored data and signatures** there is nothing to shadow, by design:
- vpqc has no classical-only mode for confidentiality: `seal` and the streaming formats are
  always hybrid, so there is no old behaviour to compare with. Migration of existing data
  is re-encryption, which `vpqc lint` helps to plan and docs/PERFORMANCE.md sizes.
- Signatures in `standard` are composite: both Ed25519 and ML-DSA must verify, which already is
  the "run both" mode. Verifiers of the old classical signature keep their own code until
  they are migrated.

### No global kill-switch
A system-wide configuration that selects the profile at run time would be a **downgrade lever**:
an attacker who controls an environment variable, a config file or a feature flag could move the
system to a weaker profile, which is the class of attack the design closes (ADR-0005). Instead:
- the profile is a property of the **key**, and the algorithm identifier is inside the
  authenticated data of every object; no setting changes how existing data is verified;
- changing profile means **new keys**, and for stored data `vpqc rewrap` changes the recipients
  of an envelope without re-encrypting the data (ADR-0009), which is the rotation operation;
- a break of one component does not need a switch: the default profiles are hybrid or composite,
  so they stay as strong as the remaining component (ADR-0003).

## Consequences
- The response to a break is an **operational procedure**, documented in docs/GUIDE.md section 5:
  decide the replacement profile, generate new keys, rewrap envelopes, re-issue certificates and
  tokens, retire the old keys.
- Teams that want a central setting can keep the profile name in their own configuration and
  pass it to key generation; the library will not read it by itself.
- If a future component break makes an algorithm unsafe to *verify* with, a library release would
  remove it (new format version, ADR-0005), not a flag.
