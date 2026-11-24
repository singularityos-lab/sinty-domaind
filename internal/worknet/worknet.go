// Package worknet decides whether the device is on its organisation's
// network: the directory must answer over TLS with the certificate pinned
// when the device joined.
package worknet

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const Dir = "/run/sinty-domaind"

func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func Fetch(ctx context.Context, addr string) (string, error) {
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}, NetDialer: &net.Dialer{Timeout: 5 * time.Second}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("the directory sent no certificate")
	}
	return Pin(certs[0]), nil
}

func Verify(ctx context.Context, addr, pin string) bool {
	if pin == "" {
		return false
	}
	got, err := Fetch(ctx, addr)
	return err == nil && strings.EqualFold(got, pin)
}

func Publish(dir, connection string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "network")
	if connection == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(connection+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
