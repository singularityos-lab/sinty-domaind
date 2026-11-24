package krb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	AES128 = 17
	AES256 = 18
)

const (
	usageEncTimestamp  = 1
	usageASRepPart     = 3
	usageTGSRepPart    = 8
	usageAuthenticator = 7
	usageTicket        = 2
	usageReqChecksum   = 6
)

var ErrIntegrity = errors.New("krb: message failed its integrity check")

type Key struct {
	Type  int32
	Value []byte
}

func keySize(etype int32) (int, error) {
	switch etype {
	case AES128:
		return 16, nil
	case AES256:
		return 32, nil
	}
	return 0, fmt.Errorf("krb: encryption type %d is not supported", etype)
}

func nfold(in []byte, n int) []byte {
	inBits := len(in) * 8
	outBits := n * 8
	lcm := lcm(inBits, outBits)
	buf := make([]byte, lcm/8)
	for i := 0; i < lcm/inBits; i++ {
		rot := rotateRight(in, 13*i)
		copy(buf[i*len(in):], rot)
	}
	out := make([]byte, n)
	for start := 0; start < len(buf); start += n {
		carry := 0
		for j := n - 1; j >= 0; j-- {
			sum := int(out[j]) + int(buf[start+j]) + carry
			out[j] = byte(sum)
			carry = sum >> 8
		}
		for carry != 0 {
			for j := n - 1; j >= 0 && carry != 0; j-- {
				sum := int(out[j]) + carry
				out[j] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	return out
}

func rotateRight(in []byte, bits int) []byte {
	n := len(in) * 8
	bits %= n
	out := make([]byte, len(in))
	for i := 0; i < n; i++ {
		src := (i - bits + n) % n
		if in[src/8]&(0x80>>(src%8)) != 0 {
			out[i/8] |= 0x80 >> (i % 8)
		}
	}
	return out
}

func lcm(a, b int) int {
	x, y := a, b
	for y != 0 {
		x, y = y, x%y
	}
	return a / x * b
}

func ctsEncrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(plain) < aes.BlockSize {
		return nil, errors.New("krb: message shorter than a block")
	}
	if len(plain) == aes.BlockSize {
		out := make([]byte, aes.BlockSize)
		block.Encrypt(out, plain)
		return out, nil
	}
	pad := (aes.BlockSize - len(plain)%aes.BlockSize) % aes.BlockSize
	buf := append(append([]byte(nil), plain...), make([]byte, pad)...)
	out := make([]byte, len(buf))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(out, buf)
	n := len(out)
	last := append([]byte(nil), out[n-aes.BlockSize:]...)
	prev := out[n-2*aes.BlockSize : n-aes.BlockSize]
	res := append(append([]byte(nil), out[:n-2*aes.BlockSize]...), last...)
	return append(res, prev[:aes.BlockSize-pad]...), nil
}

func ctsDecrypt(key, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct) < aes.BlockSize {
		return nil, ErrIntegrity
	}
	if len(ct) == aes.BlockSize {
		out := make([]byte, aes.BlockSize)
		block.Decrypt(out, ct)
		return out, nil
	}
	tail := len(ct) % aes.BlockSize
	if tail == 0 {
		tail = aes.BlockSize
	}
	full := len(ct) - tail - aes.BlockSize
	head := ct[:full]
	cn1 := ct[full : full+aes.BlockSize]
	cn := ct[full+aes.BlockSize:]
	dn := make([]byte, aes.BlockSize)
	block.Decrypt(dn, cn1)
	last := append(append([]byte(nil), cn...), dn[tail:]...)
	pn := make([]byte, tail)
	for i := range pn {
		pn[i] = dn[i] ^ cn[i]
	}
	iv := make([]byte, aes.BlockSize)
	if full > 0 {
		iv = head[full-aes.BlockSize:]
	}
	pn1 := make([]byte, aes.BlockSize)
	block.Decrypt(pn1, last)
	for i := range pn1 {
		pn1[i] ^= iv[i]
	}
	out := make([]byte, 0, len(ct))
	if full > 0 {
		dec := make([]byte, full)
		cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(dec, head)
		out = append(out, dec...)
	}
	return append(append(out, pn1...), pn...), nil
}

func derive(key, constant []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	in := nfold(constant, aes.BlockSize)
	out := make([]byte, 0, len(key))
	for len(out) < len(key) {
		next := make([]byte, aes.BlockSize)
		block.Encrypt(next, in)
		out = append(out, next...)
		in = next
	}
	return out[:len(key)], nil
}

func StringToKey(etype int32, password, salt string, iterations int) (Key, error) {
	size, err := keySize(etype)
	if err != nil {
		return Key{}, err
	}
	if iterations == 0 {
		iterations = 4096
	}
	tkey, err := pbkdf2.Key(sha1.New, password, []byte(salt), iterations, size)
	if err != nil {
		return Key{}, err
	}
	k, err := derive(tkey, []byte("kerberos"))
	if err != nil {
		return Key{}, err
	}
	return Key{Type: etype, Value: k}, nil
}

func usageKey(k Key, usage uint32, kind byte) ([]byte, error) {
	c := binary.BigEndian.AppendUint32(nil, usage)
	return derive(k.Value, append(c, kind))
}

func Encrypt(k Key, usage uint32, plain []byte) ([]byte, error) {
	ke, err := usageKey(k, usage, 0xAA)
	if err != nil {
		return nil, err
	}
	ki, err := usageKey(k, usage, 0x55)
	if err != nil {
		return nil, err
	}
	conf := make([]byte, aes.BlockSize)
	if _, err := rand.Read(conf); err != nil {
		return nil, err
	}
	msg := append(conf, plain...)
	ct, err := ctsEncrypt(ke, msg)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha1.New, ki)
	mac.Write(msg)
	return append(ct, mac.Sum(nil)[:12]...), nil
}

func Decrypt(k Key, usage uint32, data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize+12 {
		return nil, ErrIntegrity
	}
	ke, err := usageKey(k, usage, 0xAA)
	if err != nil {
		return nil, err
	}
	ki, err := usageKey(k, usage, 0x55)
	if err != nil {
		return nil, err
	}
	ct, sum := data[:len(data)-12], data[len(data)-12:]
	msg, err := ctsDecrypt(ke, ct)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha1.New, ki)
	mac.Write(msg)
	if !hmac.Equal(mac.Sum(nil)[:12], sum) {
		return nil, ErrIntegrity
	}
	return msg[aes.BlockSize:], nil
}

func checksumType(etype int32) int32 {
	if etype == AES128 {
		return 15
	}
	return 16
}

func Checksum(k Key, usage uint32, data []byte) ([]byte, error) {
	kc, err := usageKey(k, usage, 0x99)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha1.New, kc)
	mac.Write(data)
	return mac.Sum(nil)[:12], nil
}
