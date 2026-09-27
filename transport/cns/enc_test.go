package cns

import (
	"encoding/base64"
	"testing"
)

func TestXorcryptKeepsStreamPosition(t *testing.T) {
	password := []byte("key")
	plain := []byte("CNS stream payload")
	encrypted := append([]byte(nil), plain...)

	sub := Xorcrypt(encrypted[:5], password, 0)
	Xorcrypt(encrypted[5:], password, sub)
	if string(encrypted) == string(plain) {
		t.Fatal("ciphertext unexpectedly equals plaintext")
	}

	sub = Xorcrypt(encrypted[:2], password, 0)
	sub = Xorcrypt(encrypted[2:11], password, sub)
	Xorcrypt(encrypted[11:], password, sub)
	if string(encrypted) != string(plain) {
		t.Fatalf("round trip = %q, want %q", encrypted, plain)
	}
}

func TestEncryptHost(t *testing.T) {
	if got := EncryptHost("example.com:443", ""); got != "example.com:443" {
		t.Fatalf("unencrypted host = %q", got)
	}

	const password = "key"
	got := EncryptHost("example.com:443", password)
	data, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatal(err)
	}
	Xorcrypt(data, []byte(password), 0)
	if want := "example.com:443\x00"; string(data) != want {
		t.Fatalf("decoded host = %q, want %q", data, want)
	}
}

func TestDecryptHostRoundTrip(t *testing.T) {
	const host = "example.com:443"
	got, err := DecryptHost(EncryptHost(host, "key"), "key")
	if err != nil {
		t.Fatal(err)
	}
	if got != host {
		t.Fatalf("DecryptHost = %q, want %q", got, host)
	}
	got, err = DecryptHost(host, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != host {
		t.Fatalf("unencrypted DecryptHost = %q", got)
	}
}
