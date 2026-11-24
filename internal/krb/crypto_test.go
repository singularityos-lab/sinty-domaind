package krb

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNFoldMatchesRFC3961(t *testing.T) {
	cases := []struct {
		in   string
		bits int
		out  string
	}{
		{"012345", 64, "be072631276b1955"},
		{"password", 56, "78a07b6caf85fa"},
		{"Rough Consensus, and Running Code", 64, "bb6ed30870b7f0e0"},
		{"password", 168, "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"},
		{"kerberos", 64, "6b65726265726f73"},
		{"kerberos", 128, "6b65726265726f737b9b5b2b93132b93"},
		{"kerberos", 256, "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4"},
	}
	for _, c := range cases {
		got := nfold([]byte(c.in), c.bits/8)
		if hex.EncodeToString(got) != c.out {
			t.Errorf("%d-fold(%q) = %x, want %s", c.bits, c.in, got, c.out)
		}
	}
}

func TestStringToKeyMatchesRFC3962(t *testing.T) {
	cases := []struct {
		iter   int
		pass   string
		salt   string
		aes128 string
		aes256 string
	}{
		{1, "password", "ATHENA.MIT.EDUraeburn", "42263c6e89f4fc28b8df68ee09799f15",
			"fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"},
		{2, "password", "ATHENA.MIT.EDUraeburn", "c651bf29e2300ac27fa469d693bdda13",
			"a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff"},
		{1200, "password", "ATHENA.MIT.EDUraeburn", "4c01cd46d632d01e6dbe230a01ed642a",
			"55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a"},
	}
	for _, c := range cases {
		k, err := StringToKey(AES128, c.pass, c.salt, c.iter)
		if err != nil || hex.EncodeToString(k.Value) != c.aes128 {
			t.Errorf("aes128 iter %d: %x %v", c.iter, k.Value, err)
		}
		k, err = StringToKey(AES256, c.pass, c.salt, c.iter)
		if err != nil || hex.EncodeToString(k.Value) != c.aes256 {
			t.Errorf("aes256 iter %d: %x %v", c.iter, k.Value, err)
		}
	}
}

func TestCiphertextStealingMatchesRFC3962(t *testing.T) {
	key := []byte("chicken teriyaki")
	plain := "I would like the General Gau's Chicken, please, and wonton soup."
	cases := []struct {
		n   int
		out string
	}{
		{17, "c6353568f2bf8cb4d8a580362da7ff7f97"},
		{31, "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5"},
		{32, "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584"},
		{47, "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5"},
		{48, "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8"},
		{64, "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8"},
	}
	for _, c := range cases {
		ct, err := ctsEncrypt(key, []byte(plain[:c.n]))
		if err != nil || hex.EncodeToString(ct) != c.out {
			t.Errorf("encrypt %d: %x %v", c.n, ct, err)
			continue
		}
		back, err := ctsDecrypt(key, unhex(t, c.out))
		if err != nil || string(back) != plain[:c.n] {
			t.Errorf("decrypt %d: %q %v", c.n, back, err)
		}
	}
}

func TestSealedMessagesOpenOnlyWithTheirKeyAndUsage(t *testing.T) {
	k, _ := StringToKey(AES256, "s3cret", "EXAMPLE.TESTalice", 0)
	msg := []byte("an encrypted timestamp, or anything else")
	ct, err := Encrypt(k, usageEncTimestamp, msg)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decrypt(k, usageEncTimestamp, ct)
	if err != nil || !bytes.Equal(back, msg) {
		t.Fatalf("%q %v", back, err)
	}
	if _, err := Decrypt(k, usageASRepPart, ct); err != ErrIntegrity {
		t.Fatal("opened with another usage")
	}
	other, _ := StringToKey(AES256, "s3creT", "EXAMPLE.TESTalice", 0)
	if _, err := Decrypt(other, usageEncTimestamp, ct); err != ErrIntegrity {
		t.Fatal("opened with another key")
	}
	ct[5] ^= 1
	if _, err := Decrypt(k, usageEncTimestamp, ct); err != ErrIntegrity {
		t.Fatal("tampered message opened")
	}
}
