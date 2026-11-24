package krb

import (
	"context"
	"errors"
	"os"
	"testing"
)

func realKDC(t *testing.T) *Client {
	addr := os.Getenv("KRB_TEST_KDC")
	if addr == "" {
		t.Skip("set KRB_TEST_KDC to a domain controller for EXAMPLE.TEST")
	}
	return &Client{Realm: "EXAMPLE.TEST", KDCs: []string{addr}}
}

func TestALoginAgainstARealDomainController(t *testing.T) {
	c := realKDC(t)
	ctx := context.Background()
	tgt, err := c.Login(ctx, "alice", "Corr3ct horse")
	if err != nil {
		t.Fatal(err)
	}
	if tgt.User.String() != "alice" || tgt.Realm != "EXAMPLE.TEST" || len(tgt.SessionKey.Value) == 0 {
		t.Fatalf("%+v", tgt)
	}
	machine, err := StringToKey(AES256, "machine secret 42", "EXAMPLE.TESThostpc.example.test", 0)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.Service(ctx, tgt, Principal(NameTypeHost, "host", "pc.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	realm, who, err := OpenTicket(st.Ticket, machine)
	if err != nil || realm != "EXAMPLE.TEST" || who.String() != "alice" {
		t.Fatalf("ticket for %s@%s: %v", who, realm, err)
	}
	wrongMachine, _ := StringToKey(AES256, "machine secret 43", "EXAMPLE.TESThostpc.example.test", 0)
	if _, _, err := OpenTicket(st.Ticket, wrongMachine); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("a ticket opened with the wrong machine key: %v", err)
	}
	if _, err := c.Login(ctx, "bob", "no preauth here"); err != nil {
		t.Fatalf("user without pre-authentication: %v", err)
	}
}

func TestTheDomainControllerSaysWhyALoginFails(t *testing.T) {
	c := realKDC(t)
	ctx := context.Background()
	code := func(user, pass string) int32 {
		_, err := c.Login(ctx, user, pass)
		var e *Error
		if !errors.As(err, &e) {
			t.Fatalf("%s: %v", user, err)
		}
		return e.Code
	}
	if got := code("alice", "Wrong horse"); got != ErrPreauthFailed {
		t.Errorf("wrong password: %d", got)
	}
	if got := code("nobody", "x"); got != ErrPrincipalUnknown {
		t.Errorf("unknown user: %d", got)
	}
	if got := code("carol", "Carol pass 1"); got != ErrClientRevoked {
		t.Errorf("disabled user: %d", got)
	}
	if got := code("dave", "Dave pass 1"); got != ErrKeyExpired {
		t.Errorf("expired password: %d", got)
	}
	if got := code("bob", "wrong but no preauth"); got != ErrPreauthFailed {
		t.Errorf("wrong password for a user the domain does not pre-authenticate: %d", got)
	}
}
