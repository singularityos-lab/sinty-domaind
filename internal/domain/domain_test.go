package domain

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-domaind/internal/krb"
)

type away struct{}

func (away) Login(context.Context, string, string) (*krb.TGT, error) {
	return nil, &net.OpError{Op: "dial", Err: errors.New("connection refused")}
}

func (away) Service(context.Context, *krb.TGT, krb.PrincipalName) (*krb.ServiceTicket, error) {
	return nil, errors.New("unused")
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func offlineDomain(t *testing.T) (*Domain, *clock) {
	clk := &clock{t: time.Date(2026, 11, 24, 20, 0, 0, 0, time.UTC)}
	d := New(t.TempDir())
	d.Now = clk.now
	d.Dial = func(Join) KDC { return away{} }
	if err := d.Join(context.Background(), Join{Realm: "EXAMPLE.TEST", Host: "pc.example.test", Machine: "m"}); err != nil {
		t.Fatal(err)
	}
	return d, clk
}

func TestOfflineSignInLastsAsLongAsTheLease(t *testing.T) {
	d, clk := offlineDomain(t)
	ctx := context.Background()
	if _, err := d.Login(ctx, "alice", "pw"); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("never signed in: %v", err)
	}
	writeJSON(d.userPath("alice"), lease{Until: clk.t.Add(7 * 24 * time.Hour)})
	r, err := d.Login(ctx, "alice", "pw")
	if err != nil || !r.Offline {
		t.Fatalf("%+v %v", r, err)
	}
	clk.t = clk.t.Add(7*24*time.Hour + time.Second)
	if _, err := d.Login(ctx, "alice", "pw"); !errors.Is(err, ErrOfflineStale) {
		t.Fatalf("after the lease: %v", err)
	}
}

func TestNothingThatCouldRevealThePasswordIsKept(t *testing.T) {
	addr := os.Getenv("KRB_TEST_KDC")
	if addr == "" {
		t.Skip("set KRB_TEST_KDC to a domain controller for EXAMPLE.TEST")
	}
	d := realDomain(t, "machine secret 42")
	if _, err := d.Login(context.Background(), "alice", "Corr3ct horse"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(d.userPath("alice"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	json.Unmarshal(b, &fields)
	if len(fields) != 1 || fields["until"] == nil {
		t.Fatalf("the cache holds more than the lease: %s", b)
	}
	if info, _ := os.Stat(d.userPath("alice")); info.Mode().Perm() != 0o600 {
		t.Fatal(info.Mode())
	}
}

func TestOnlyPlainUserNamesAreAccepted(t *testing.T) {
	d, _ := offlineDomain(t)
	for _, u := range []string{"", "../root", "a/b", "alice@EXAMPLE.TEST", ".hidden"} {
		if _, err := d.Login(context.Background(), u, "pw"); !errors.Is(err, ErrWrong) {
			t.Errorf("%q: %v", u, err)
		}
	}
}

func TestNothingWorksBeforeJoining(t *testing.T) {
	d := New(t.TempDir())
	if _, err := d.Login(context.Background(), "alice", "pw"); !errors.Is(err, ErrNotJoined) {
		t.Fatal(err)
	}
}

func TestLeavingForgetsEveryAccount(t *testing.T) {
	d, clk := offlineDomain(t)
	writeJSON(d.userPath("alice"), lease{Until: clk.t.Add(time.Hour)})
	if err := d.Leave(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d.userPath("alice")); !os.IsNotExist(err) {
		t.Fatal("lease left behind")
	}
	if _, err := d.Joined(); !errors.Is(err, ErrNotJoined) {
		t.Fatal(err)
	}
}

func realDomain(t *testing.T, machine string) *Domain {
	addr := os.Getenv("KRB_TEST_KDC")
	if addr == "" {
		t.Skip("set KRB_TEST_KDC to a domain controller for EXAMPLE.TEST")
	}
	d := New(t.TempDir())
	if err := d.Join(context.Background(), Join{Realm: "EXAMPLE.TEST", Host: "pc.example.test", Machine: machine, KDCs: []string{addr}}); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSigningInWithTheDomainAndThenWithoutIt(t *testing.T) {
	d := realDomain(t, "machine secret 42")
	ctx := context.Background()
	r, err := d.Login(ctx, "alice", "Corr3ct horse")
	if err != nil || r.Offline {
		t.Fatalf("online: %+v %v", r, err)
	}
	if _, err := d.Login(ctx, "alice", "Wrong horse"); !errors.Is(err, ErrWrong) {
		t.Fatalf("wrong online: %v", err)
	}
	if _, err := d.Login(ctx, "carol", "Carol pass 1"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	if _, err := d.Login(ctx, "dave", "Dave pass 1"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	j, _ := d.Joined()
	j.KDCs = []string{"127.0.0.1:1"}
	d.Join(ctx, j)
	if r, err := d.Login(ctx, "alice", "Corr3ct horse"); err != nil || !r.Offline {
		t.Fatalf("offline: %+v %v", r, err)
	}
	if _, err := d.Login(ctx, "bob", "no preauth here"); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("never signed in here: %v", err)
	}
}

func TestAControllerThatDoesNotKnowTheDeviceIsRefused(t *testing.T) {
	d := realDomain(t, "not the machine secret")
	if _, err := d.Login(context.Background(), "alice", "Corr3ct horse"); !errors.Is(err, ErrSpoofed) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(d.userPath("alice")); !os.IsNotExist(err) {
		t.Fatal("a spoofed sign-in was cached")
	}
}
