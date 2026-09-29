package vpqc

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

var profiles = []Profile{ProfileStandard, ProfileFastAuth, ProfileCNSA2, ProfileHigh}

func TestABIVersion(t *testing.T) {
	if ABIVersion()>>16 != 1 {
		t.Fatalf("unexpected ABI version %x", ABIVersion())
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	for _, p := range profiles {
		pk, sk, err := GenerateEncryptionKeypair(p)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := Seal(pk, []byte("secret"), []byte("ctx"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Open(sk, sealed, []byte("ctx"))
		if err != nil || !bytes.Equal(got, []byte("secret")) {
			t.Fatalf("profile %d: got %q err %v", p, got, err)
		}
	}
}

func TestDecryptionFailures(t *testing.T) {
	pk, sk, _ := GenerateEncryptionKeypair(ProfileStandard)
	_, other, _ := GenerateEncryptionKeypair(ProfileStandard)
	sealed, _ := Seal(pk, []byte("secret"), []byte("one"))
	if _, err := Open(sk, sealed, []byte("two")); !errors.Is(err, ErrDecryption) {
		t.Fatalf("wrong aad: %v", err)
	}
	if _, err := Open(other, sealed, []byte("one")); !errors.Is(err, ErrDecryption) {
		t.Fatalf("wrong key: %v", err)
	}
	for _, i := range []int{0, 6, 12, 500, len(sealed) - 1} {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 1
		if _, err := Open(sk, bad, []byte("one")); err == nil {
			t.Fatalf("flip at %d accepted", i)
		}
	}
}

func TestEmptyPlaintextAndNilSlices(t *testing.T) {
	pk, sk, _ := GenerateEncryptionKeypair(ProfileStandard)
	sealed, err := Seal(pk, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(sk, sealed, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestSignVerify(t *testing.T) {
	for _, p := range profiles {
		pk, sk, err := GenerateSigningKeypair(p)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := Sign(sk, []byte("msg"), []byte("app/v1"))
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(pk, []byte("msg"), []byte("app/v1"), sig); err != nil {
			t.Fatalf("profile %d: %v", p, err)
		}
		if err := Verify(pk, []byte("msg"), []byte("app/v2"), sig); !errors.Is(err, ErrVerification) {
			t.Fatalf("wrong context: %v", err)
		}
		if err := Verify(pk, []byte("other"), []byte("app/v1"), sig); !errors.Is(err, ErrVerification) {
			t.Fatalf("wrong message: %v", err)
		}
	}
}

func TestInvalidInputs(t *testing.T) {
	if _, _, err := GenerateEncryptionKeypair(Profile(42)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown profile: %v", err)
	}
	spk, ssk, _ := GenerateSigningKeypair(ProfileStandard)
	if _, err := Seal(spk, []byte("x"), nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("signing key cannot encrypt: %v", err)
	}
	if _, err := Sign(ssk, []byte("m"), bytes.Repeat([]byte{1}, 256)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("long context: %v", err)
	}
	if _, err := Seal(PublicKeyFromBytes([]byte{1, 2, 3}), nil, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("garbage key: %v", err)
	}
	var e *Error
	if _, err := Seal(PublicKeyFromBytes(nil), nil, nil); !errors.As(err, &e) || e.Code == 0 {
		t.Fatalf("expected *Error, got %v", err)
	}
}

func TestSecretKeyIsNotPrinted(t *testing.T) {
	_, sk, _ := GenerateEncryptionKeypair(ProfileStandard)
	for _, s := range []string{fmt.Sprintf("%v", sk), fmt.Sprintf("%+v", sk), fmt.Sprintf("%x", sk), fmt.Sprintf("%#v", sk), sk.String()} {
		if s != "vpqc.SecretKey(<redacted>)" {
			t.Fatalf("secret key leaked through formatting: %q", s)
		}
	}
}

func TestLargeMessage(t *testing.T) {
	pk, sk, _ := GenerateEncryptionKeypair(ProfileStandard)
	data := make([]byte, 1<<20)
	for i := range data {
		data[i] = byte(i)
	}
	sealed, err := Seal(pk, data, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(sk, sealed, nil)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("large message round trip failed: %v", err)
	}
}

func TestConcurrentUse(t *testing.T) {
	pk, sk, _ := GenerateEncryptionKeypair(ProfileStandard)
	done := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func(i int) {
			msg := []byte(fmt.Sprintf("message %d", i))
			sealed, err := Seal(pk, msg, nil)
			if err == nil {
				var got []byte
				got, err = Open(sk, sealed, nil)
				if err == nil && !bytes.Equal(got, msg) {
					err = errors.New("mismatch")
				}
			}
			done <- err
		}(i)
	}
	for i := 0; i < 16; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestKeyText(t *testing.T) {
	pk, sk, _ := GenerateEncryptionKeypair(ProfileStandard)
	pt, err := pk.Text()
	if err != nil {
		t.Fatal(err)
	}
	st, err := sk.Text()
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := PublicKeyFromText(pt)
	if err != nil || !bytes.Equal(pk2.Bytes(), pk.Bytes()) {
		t.Fatalf("public key text round trip: %v", err)
	}
	sk2, err := SecretKeyFromText(st)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := Seal(pk2, []byte("x"), nil)
	if got, err := Open(sk2, sealed, nil); err != nil || string(got) != "x" {
		t.Fatalf("restored key cannot decrypt: %v", err)
	}
	if _, err := PublicKeyFromText(st); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("secret text accepted as public key: %v", err)
	}
}
