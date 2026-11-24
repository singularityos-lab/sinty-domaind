package worknet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func selfSigned(t *testing.T) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"dc.example.test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestOnlyThePinnedDirectoryMakesAWorkNetwork(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	other := httptest.NewTLSServer(http.NotFoundHandler())
	defer other.Close()
	addr := srv.Listener.Addr().String()
	pin, err := Fetch(context.Background(), addr)
	if err != nil || len(pin) != 64 {
		t.Fatalf("%q %v", pin, err)
	}
	if pin != Pin(srv.Certificate()) {
		t.Fatal("pin differs from the certificate")
	}
	ctx := context.Background()
	if !Verify(ctx, addr, pin) {
		t.Fatal("the pinned directory was not recognised")
	}
	impostor := httptest.NewUnstartedServer(http.NotFoundHandler())
	impostor.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	impostor.StartTLS()
	defer impostor.Close()
	if Verify(ctx, impostor.Listener.Addr().String(), pin) {
		t.Fatal("a directory with another key was taken for the organisation's")
	}
	if Verify(ctx, addr, "") || Verify(ctx, "127.0.0.1:1", pin) {
		t.Fatal("no pin or no directory must never mean work")
	}
}

func TestThePublishedConnectionIsWhatSintyNmReads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sinty-domaind")
	if err := Publish(dir, "1b4e28ba-2fa1-11d2-883f-0016d3cca427"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "network"))
	if string(b) != "1b4e28ba-2fa1-11d2-883f-0016d3cca427\n" {
		t.Fatalf("%q", b)
	}
	Publish(dir, "")
	if _, err := os.Stat(filepath.Join(dir, "network")); !os.IsNotExist(err) {
		t.Fatal("left behind")
	}
}
