package service

import (
	"bufio"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-domaind/internal/domain"
)

func bus(t *testing.T) string {
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not installed")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address")
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	addr, _ := bufio.NewReader(out).ReadString('\n')
	return strings.TrimSpace(addr)
}

func connect(t *testing.T, addr string) *dbus.Conn {
	c, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func errName(err error) string {
	var de dbus.Error
	if errors.As(err, &de) {
		return strings.TrimPrefix(de.Name, Iface+".Error.")
	}
	return ""
}

func TestOnlyTheSystemCanJoinOrCheckPasswords(t *testing.T) {
	addr := bus(t)
	server := connect(t, addr)
	uid := uint32(1000)
	svc := &Service{D: domain.New(t.TempDir()), Caller: func(dbus.Sender) (uint32, error) { return uid, nil }}
	if err := Export(server, svc); err != nil {
		t.Fatal(err)
	}
	server.RequestName(Name, dbus.NameFlagDoNotQueue)
	obj := connect(t, addr).Object(Name, Path)

	if err := obj.Call(Iface+".Join", 0, "EXAMPLE.TEST", "pc.example.test", "secret", []string{"127.0.0.1:1"}, "", "").Err; errName(err) != "NotAllowed" {
		t.Fatalf("a desktop user joined: %v", err)
	}
	if err := obj.Call(Iface+".Login", 0, "alice", "pw").Err; errName(err) != "NotAllowed" {
		t.Fatalf("a desktop user checked a password: %v", err)
	}
	uid = 0
	if err := obj.Call(Iface+".Login", 0, "alice", "pw").Err; errName(err) != "NotJoined" {
		t.Fatalf("before joining: %v", err)
	}
	if err := obj.Call(Iface+".Join", 0, "EXAMPLE.TEST", "pc.example.test", "secret", []string{"127.0.0.1:1"}, "", "").Err; err != nil {
		t.Fatal(err)
	}
	var joined, work bool
	var realm, host string
	if err := obj.Call(Iface+".Status", 0).Store(&joined, &realm, &host, &work); err != nil || !joined || realm != "EXAMPLE.TEST" || host != "pc.example.test" || work {
		t.Fatalf("status %v %s %s %v %v", joined, realm, host, work, err)
	}
	if err := obj.Call(Iface+".Login", 0, "alice", "pw").Err; errName(err) != "NeedsNetwork" {
		t.Fatalf("never signed in and no controller: %v", err)
	}
	uid = 1000
	if err := obj.Call(Iface+".Leave", 0).Err; errName(err) != "NotAllowed" {
		t.Fatalf("a desktop user left the domain: %v", err)
	}
	uid = 0
	if err := obj.Call(Iface+".Leave", 0).Err; err != nil {
		t.Fatal(err)
	}
	obj.Call(Iface+".Status", 0).Store(&joined, &realm, &host, &work)
	if joined {
		t.Fatal("still joined")
	}
}
