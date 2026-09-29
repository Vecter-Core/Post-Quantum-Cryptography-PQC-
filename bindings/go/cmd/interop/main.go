// Command interop is the Go driver for the cross-language interoperability suite.
// Usage mirrors interop/drivers: keygen|seal|open|sign|verify (see interop/run.sh).
package main

import (
	"fmt"
	"os"
	"strconv"

	vpqc "github.com/Vecter-Core/Post-Quantum-Cryptography-PQC-/bindings/go"
)

func die(err error) {
	fmt.Fprintln(os.Stderr, "go-driver:", err)
	os.Exit(1)
}

func read(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		die(err)
	}
	return b
}

func write(path string, b []byte) {
	if err := os.WriteFile(path, b, 0o600); err != nil {
		die(err)
	}
}

func main() {
	a := os.Args[1:]
	if len(a) < 1 {
		die(fmt.Errorf("missing command"))
	}
	switch a[0] {
	case "keygen": // keygen encrypt|sign PROFILE_ID OUT_PREFIX
		p, _ := strconv.Atoi(a[2])
		gen := vpqc.GenerateEncryptionKeypair
		if a[1] == "sign" {
			gen = vpqc.GenerateSigningKeypair
		}
		pk, sk, err := gen(vpqc.Profile(p))
		if err != nil {
			die(err)
		}
		pt, _ := pk.Text()
		st, _ := sk.Text()
		write(a[3]+".pub", []byte(pt))
		write(a[3]+".sec", []byte(st))
	case "seal": // seal PUBFILE AAD IN OUT
		pk, err := vpqc.PublicKeyFromText(string(read(a[1])))
		if err != nil {
			die(err)
		}
		out, err := vpqc.Seal(pk, read(a[3]), []byte(a[2]))
		if err != nil {
			die(err)
		}
		write(a[4], out)
	case "open": // open SECFILE AAD IN OUT
		sk, err := vpqc.SecretKeyFromText(string(read(a[1])))
		if err != nil {
			die(err)
		}
		out, err := vpqc.Open(sk, read(a[3]), []byte(a[2]))
		if err != nil {
			die(err)
		}
		write(a[4], out)
	case "sign": // sign SECFILE CTX IN OUT
		sk, err := vpqc.SecretKeyFromText(string(read(a[1])))
		if err != nil {
			die(err)
		}
		out, err := vpqc.Sign(sk, read(a[3]), []byte(a[2]))
		if err != nil {
			die(err)
		}
		write(a[4], out)
	case "verify": // verify PUBFILE CTX SIG IN
		pk, err := vpqc.PublicKeyFromText(string(read(a[1])))
		if err != nil {
			die(err)
		}
		if err := vpqc.Verify(pk, read(a[4]), []byte(a[2]), read(a[3])); err != nil {
			die(err)
		}
	case "encrypt-file": // encrypt-file PUBFILE AAD IN OUT
		pk, err := vpqc.PublicKeyFromText(string(read(a[1])))
		if err != nil {
			die(err)
		}
		if _, err := vpqc.EncryptFile(pk, a[3], a[4], []byte(a[2])); err != nil {
			die(err)
		}
	case "encrypt-file-multi": // encrypt-file-multi AAD IN OUT PUBFILE...
		var pks []vpqc.PublicKey
		for _, f := range a[4:] {
			pk, err := vpqc.PublicKeyFromText(string(read(f)))
			if err != nil {
				die(err)
			}
			pks = append(pks, pk)
		}
		if _, err := vpqc.EncryptFileMulti(pks, a[2], a[3], []byte(a[1])); err != nil {
			die(err)
		}
	case "rewrap-file": // rewrap-file SECFILE AAD IN OUT PUBFILE...
		sk, err := vpqc.SecretKeyFromText(string(read(a[1])))
		if err != nil {
			die(err)
		}
		var pks []vpqc.PublicKey
		for _, f := range a[5:] {
			pk, err := vpqc.PublicKeyFromText(string(read(f)))
			if err != nil {
				die(err)
			}
			pks = append(pks, pk)
		}
		if _, err := vpqc.RewrapFile(sk, pks, a[3], a[4], []byte(a[2])); err != nil {
			die(err)
		}
	case "decrypt-file": // decrypt-file SECFILE AAD IN OUT
		sk, err := vpqc.SecretKeyFromText(string(read(a[1])))
		if err != nil {
			die(err)
		}
		if _, err := vpqc.DecryptFile(sk, a[3], a[4], []byte(a[2])); err != nil {
			die(err)
		}
	default:
		die(fmt.Errorf("unknown command %q", a[0]))
	}
}
