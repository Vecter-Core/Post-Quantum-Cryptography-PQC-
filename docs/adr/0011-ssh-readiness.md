# ADR-0011: SSH post-quantum readiness: use OpenSSH's hybrids, probe and audit

- Status: accepted
- Date: 2026-09-29

## Context
SSH key exchange is a tier-0 item (ADR-0003): a recorded session can be decrypted later if
its (EC)DH exchange falls ("harvest now, decrypt later"). Unlike TLS, the fix already ships:
- OpenSSH has hybrid key exchanges:
  - `sntrup761x25519-sha512@openssh.com` is the default since 9.0 (2022);
  - `mlkem768x25519-sha256` (ML-KEM-768 + X25519, FIPS 203) exists since 9.9 and is the
    default since 10.0.
- The IETF SSHM working group specifies both, together with the NIST-curve variants
  `mlkem768nistp256-sha256` and `mlkem1024nistp384-sha384`.

What goes wrong in practice is configuration and fleet visibility:
- hardening guides from before 2022 pin `KexAlgorithms` to classical lists;
- `-sntrup*` style removals silently drop every hybrid;
- old servers and appliances (network gear, embedded dropbear) never offer one.

Host keys and user authentication are signatures. They only need to resist a quantum
computer at the moment of the connection, so they are tier 2 and not the urgent part.

## Decision
- **Do not implement an SSH stack or new key exchange.** Rely on OpenSSH's hybrids (the
  ROADMAP integration table planned). vpqc provides the
  tooling to find and fix the gaps, in a new dependency-free crate `vpqc-ssh`:
  - `probe`: connects and reads the server's `SSH_MSG_KEXINIT`. RFC 4253 sends it in the
    clear right after the identification strings, before any key exchange or
    authentication. The probe classifies the offered algorithms and disconnects, so it
    never logs in and needs no credentials. CLI: `vpqc ssh probe host[:port]
    [--require-pq] [--json]`, where exit status 2 means no hybrid, for CI and fleet
    scripts.
  - `audit_kex_directive`: evaluates an OpenSSH `KexAlgorithms` value with its real
    semantics:
    - `+list` appends and `^list` prepends, so the default hybrids stay;
    - `-pattern` removes with wildcards, so it is flagged only if every default hybrid is
      removed;
    - an explicit list is flagged if it has no hybrid.

    For client configurations, a hybrid that is present but not first is reported: the
    client's order decides, so it would prefer classical.
  - `vpqc scan` applies the audit to `sshd_config`, `ssh_config` and their `*.d/*.conf`
    drop-ins. A classical-only or hybrid-removing setting is a T0 finding.
- **Classification.**
  - `mlkem*` hybrids are the preferred post-quantum class (NIST ML-KEM).
  - `sntrup761x25519` is also accepted as post-quantum: it is hybrid, and X25519 keeps the
    classical floor. It is labelled "not NIST" so that CNSA 2.0 / FIPS environments know
    to move to `mlkem768x25519-sha256`.
  - SHA-1 and small-group exchanges are reported as weak.
  - Unknown names are not assumed to be post-quantum.
- The probe reads exactly one packet, and its limits come from RFC 4253:
  - at most 64 pre-identification lines of up to 255 bytes;
  - a packet of 5 to 35 000 bytes;
  - algorithm names of printable ASCII, at most 64 bytes.

  A timeout bounds the connection and every read.

## Consequences
- `interop/ssh.sh` runs real, unprivileged `sshd` instances on loopback, in CI too, with six
  configurations: default, classical list, `-sntrup*,mlkem*`, `+dh-group14`, an sntrup-first
  list, and ML-KEM-only where the installed OpenSSH has it. For each one it checks that:
  - the probed list equals what `sshd -T` says the server offers;
  - `--require-pq` exits 0 or 2 as expected;
  - a real `ssh` client negotiates a hybrid exactly when the probe says one is offered;
  - the scanner rates the same `sshd_config` consistently.
- Integration tests cover TCP fake servers (banners, SSH-1, bad lengths, wrong first message,
  early close, silence and timeout) and malformed `KEXINIT` payloads. A fuzz target checks
  that parsing never panics and round-trips. Within minutes, fuzzing found two real
  denial-of-service bugs in untrusted configuration input, both now fixed with regression
  tests:
  - the textbook recursive wildcard matcher is exponential on `-*****...*x`; it is replaced
    by an iterative O(pattern x name) matcher, checked against the recursion on every short
    input;
  - a keyword slice split a multi-byte UTF-8 character and panicked the scanner.

  CI fuzzing now runs with `-timeout=10`, so hangs fail the job.
- Recommending a name the installed OpenSSH does not know is harmful: before 9.9, `sshd`
  refuses to start on `mlkem768x25519-sha256` ("Unsupported KEX algorithm"). The advice
  therefore prefers removing the `KexAlgorithms` line (the defaults are hybrid since 9.0)
  and tells the user to run `sshd -t` first.
- Limits:
  - the probe sees what a server offers, not what a given client negotiates;
  - `Match` blocks and `Include` resolution are not evaluated: each `KexAlgorithms` line is
    judged on its own;
  - host-key algorithms are reported but not rated, because no post-quantum SSH host key is
    standardised yet.
