package account

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeSystem struct {
	users map[string]string
	calls []string
	stdin map[string]string
	fail  string
}

func (f *fakeSystem) run(_ context.Context, stdin, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if stdin != "" {
		f.stdin[name] = stdin
	}
	if f.fail != "" && strings.HasPrefix(line, f.fail) {
		return "", errors.New("failed")
	}
	switch name {
	case "useradd":
		f.users[args[len(args)-1]] = "300001"
	case "userdel":
		delete(f.users, args[0])
	case "sintykey":
		return "RECOVERY-1234\n", nil
	}
	return "", nil
}

func newFake(t *testing.T) (*Accounts, *fakeSystem) {
	f := &fakeSystem{users: map[string]string{"mirko": "1000"}, stdin: map[string]string{}}
	a := &Accounts{Dir: t.TempDir(), Home: t.TempDir(), Shell: "/usr/bin/ush", Skel: "/nonexistent", Run: f.run,
		Lookup: func(n string) (string, bool) { u, ok := f.users[n]; return u, ok }}
	return a, f
}

func TestTheFirstSignInCreatesAnEncryptedHome(t *testing.T) {
	a, f := newFake(t)
	if err := a.Ensure(context.Background(), "alice", "example.test", "Corr3ct horse"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls, "\n")
	for _, want := range []string{
		"useradd --no-create-home --home-dir " + filepath.Join(a.Home, "alice") + " --shell /usr/bin/ush --comment alice@EXAMPLE.TEST alice",
		"sintykey provision --user alice --uid 300001 --home " + filepath.Join(a.Home, "alice"),
		"usermod -p * alice",
		"usermod -aG singularity-session alice",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "wheel") || strings.Contains(joined, "sudo") || strings.Contains(joined, "sinty-policy") {
		t.Error("a domain account must not become an administrator")
	}
	if f.stdin["sintykey"] != "Corr3ct horse\n" {
		t.Errorf("the password must reach sintykey on standard input, got %q", f.stdin["sintykey"])
	}
	for _, c := range f.calls {
		if strings.Contains(c, "Corr3ct") {
			t.Fatalf("the password appeared in arguments: %s", c)
		}
	}
	b, err := os.ReadFile(a.marker("alice"))
	if err != nil || strings.TrimSpace(string(b)) != "RECOVERY-1234" {
		t.Fatalf("recovery code %q %v", b, err)
	}
	if info, _ := os.Stat(a.marker("alice")); info.Mode().Perm() != 0o600 {
		t.Fatal("the recovery code must be readable by root only")
	}
	f.calls = nil
	if err := a.Ensure(context.Background(), "alice", "example.test", "x"); err != nil || len(f.calls) != 0 {
		t.Fatalf("second sign-in touched the system: %v %v", f.calls, err)
	}
}

func TestALocalAccountIsNeverTakenOver(t *testing.T) {
	a, f := newFake(t)
	if err := a.Ensure(context.Background(), "mirko", "example.test", "pw"); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("touched the system: %v", f.calls)
	}
	if err := a.Lock(context.Background(), "mirko"); err != nil || len(f.calls) != 0 {
		t.Fatal("locked a local account")
	}
}

func TestAFailedSealLeavesNoAccountBehind(t *testing.T) {
	a, f := newFake(t)
	f.fail = "sintykey"
	if err := a.Ensure(context.Background(), "alice", "example.test", "pw"); err == nil {
		t.Fatal("no error")
	}
	if _, ok := f.users["alice"]; ok {
		t.Fatal("half-made account left behind")
	}
	if a.Owned("alice") {
		t.Fatal("marked as provisioned")
	}
}

func TestADisabledAccountIsLockedLocallyToo(t *testing.T) {
	a, f := newFake(t)
	a.Ensure(context.Background(), "alice", "example.test", "pw")
	f.calls = nil
	a.Unlock(context.Background(), "alice")
	if len(f.calls) != 0 {
		t.Fatal("unlocked an account the domain never locked")
	}
	a.Lock(context.Background(), "alice")
	a.Unlock(context.Background(), "alice")
	a.Unlock(context.Background(), "alice")
	if strings.Join(f.calls, "|") != "usermod -L alice|usermod -p * alice" {
		t.Fatal(f.calls)
	}
}
