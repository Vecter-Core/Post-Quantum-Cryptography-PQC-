"""Python driver for the interoperability suite. See interop/run.sh."""
import sys
from pathlib import Path

import vpqc


def main(argv):
    cmd, a = argv[0], argv[1:]
    if cmd == "keygen":  # keygen encrypt|sign PROFILE_NAME OUT_PREFIX
        gen = vpqc.generate_encryption_keypair if a[0] == "encrypt" else vpqc.generate_signing_keypair
        kp = gen(a[1])
        Path(a[2] + ".pub").write_text(kp.public.to_text())
        Path(a[2] + ".sec").write_text(kp.secret.to_text())
    elif cmd == "seal":  # seal PUBFILE AAD IN OUT
        pk = vpqc.PublicKey.from_text(Path(a[0]).read_text())
        Path(a[3]).write_bytes(vpqc.seal(pk, Path(a[2]).read_bytes(), aad=a[1].encode()))
    elif cmd == "open":  # open SECFILE AAD IN OUT
        sk = vpqc.SecretKey.from_text(Path(a[0]).read_text())
        Path(a[3]).write_bytes(vpqc.unseal(sk, Path(a[2]).read_bytes(), aad=a[1].encode()))
    elif cmd == "sign":  # sign SECFILE CTX IN OUT
        sk = vpqc.SecretKey.from_text(Path(a[0]).read_text())
        Path(a[3]).write_bytes(vpqc.sign(sk, Path(a[2]).read_bytes(), context=a[1].encode()))
    elif cmd == "verify":  # verify PUBFILE CTX SIG IN
        pk = vpqc.PublicKey.from_text(Path(a[0]).read_text())
        vpqc.verify(pk, Path(a[3]).read_bytes(), Path(a[2]).read_bytes(), context=a[1].encode())
    elif cmd == "encrypt-file":  # encrypt-file PUBFILE AAD IN OUT
        vpqc.encrypt_file(vpqc.PublicKey.from_text(Path(a[0]).read_text()), a[2], a[3], aad=a[1].encode())
    elif cmd == "decrypt-file":  # decrypt-file SECFILE AAD IN OUT
        vpqc.decrypt_file(vpqc.SecretKey.from_text(Path(a[0]).read_text()), a[2], a[3], aad=a[1].encode())
    else:
        raise SystemExit(f"unknown command {cmd}")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (vpqc.VpqcError, OSError) as e:
        print(f"py-driver: {e}", file=sys.stderr)
        sys.exit(1)
