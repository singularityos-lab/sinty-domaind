package gate

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/singularityos-lab/sinty-domaind/internal/account"
	"github.com/singularityos-lab/sinty-domaind/internal/domain"
)

func setup(t *testing.T, kdc string) (*Gate, *[]string) {
	d := domain.New(t.TempDir())
	if err := d.Join(context.Background(), domain.Join{Realm: "EXAMPLE.TEST", Host: "pc.example.test", Machine: "machine secret 42", KDCs: []string{kdc}}); err != nil {
		t.Fatal(err)
	}
	var calls []string
	users := map[string]string{"mirko": "1000"}
	a := &account.Accounts{Dir: t.TempDir(), Home: t.TempDir(), Shell: "/bin/sh", Skel: "/nonexistent",
		Lookup: func(n string) (string, bool) { u, ok := users[n]; return u, ok },
		Run: func(_ context.Context, stdin, name string, args ...string) (string, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			if name == "useradd" {
				users[args[len(args)-1]] = "300001"
			}
			return "", nil
		}}
	return &Gate{D: d, Accounts: a}, &calls
}

func ask(t *testing.T, path, msg string) string {
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte(msg))
	line, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(line)
}

func TestOnlyRootMayAsk(t *testing.T) {
	g, _ := setup(t, "127.0.0.1:1")
	path := filepath.Join(t.TempDir(), "s")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", info.Mode())
	}
	uid := uint32(1000)
	g.Peer = func(*net.UnixConn) (uint32, error) { return uid, nil }
	go g.Serve(ln)
	if got := ask(t, path, "login\nalice\npw\n"); got != "" {
		t.Fatalf("a user got an answer: %q", got)
	}
	uid = 0
	if got := ask(t, path, "login\nalice\npw\n"); got != "ERR NeedsNetwork" {
		t.Fatalf("%q", got)
	}
	if got := ask(t, path, "nonsense\n"); got != "" {
		t.Fatalf("%q", got)
	}
}

func TestPeerCredentialsAreReadFromTheKernel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan uint32, 1)
	go func() {
		c, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		uid, _ := peerUID(c)
		got <- uid
		c.Close()
	}()
	c, _ := net.Dial("unix", path)
	defer c.Close()
	if uid := <-got; uid != uint32(os.Getuid()) {
		t.Fatalf("peer uid %d, want %d", uid, os.Getuid())
	}
}

func TestASignInAgainstTheDomainCreatesTheAccountOnce(t *testing.T) {
	addr := os.Getenv("KRB_TEST_KDC")
	if addr == "" {
		t.Skip("set KRB_TEST_KDC to a domain controller for EXAMPLE.TEST")
	}
	g, calls := setup(t, addr)
	ctx := context.Background()
	if got := g.Login(ctx, "alice", "Wrong horse"); got != "ERR Wrong" {
		t.Fatal(got)
	}
	if len(*calls) != 0 {
		t.Fatal("a wrong password touched the system")
	}
	if got := g.Login(ctx, "alice", "Corr3ct horse"); got != "OK online" {
		t.Fatal(got)
	}
	if !g.Accounts.Owned("alice") {
		t.Fatal("no account")
	}
	n := len(*calls)
	if got := g.Login(ctx, "alice", "Corr3ct horse"); got != "OK online" || len(*calls) != n {
		t.Fatalf("%s, calls %v", got, (*calls)[n:])
	}
	if got := g.Login(ctx, "carol", "Carol pass 1"); got != "ERR Disabled" {
		t.Fatal(got)
	}
	j, _ := g.D.Joined()
	j.KDCs = []string{"127.0.0.1:1"}
	g.D.Join(ctx, j)
	if got := g.Login(ctx, "alice", "Corr3ct horse"); got != "OK offline" {
		t.Fatal(got)
	}
	if got := g.Login(ctx, "bob", "no preauth here"); got != "ERR NeedsNetwork" {
		t.Fatal(got)
	}
}
