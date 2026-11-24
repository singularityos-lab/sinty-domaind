// Package account gives a domain user a local account the first time they
// sign in: an encrypted home sealed with their domain password, the same way
// a local account is sealed with its PIN.
package account

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

var ErrConflict = errors.New("a local account with this name already exists")

var groups = []string{"singularity-session", "audio", "video", "input", "render", "seat", "netdev", "plugdev", "bluetooth"}

type Runner func(ctx context.Context, stdin string, name string, args ...string) (string, error)

type Accounts struct {
	Dir    string
	Home   string
	Shell  string
	Skel   string
	Run    Runner
	Lookup func(name string) (uid string, ok bool)
}

func New(dir string) *Accounts {
	shell := "/usr/bin/ush"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}
	return &Accounts{Dir: dir, Home: "/var/home", Shell: shell, Skel: "/etc/skel", Run: run, Lookup: lookup}
}

func run(ctx context.Context, stdin, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func lookup(name string) (string, bool) {
	u, err := user.Lookup(name)
	if err != nil {
		return "", false
	}
	return u.Uid, true
}

func (a *Accounts) marker(name string) string {
	return filepath.Join(a.Dir, "accounts", strings.ToLower(name))
}

func (a *Accounts) Owned(name string) bool {
	_, err := os.Stat(a.marker(name))
	return err == nil
}

func (a *Accounts) Ensure(ctx context.Context, name, realm, password string) error {
	if a.Owned(name) {
		return nil
	}
	if _, ok := a.Lookup(name); ok {
		return ErrConflict
	}
	home := filepath.Join(a.Home, name)
	if _, err := a.Run(ctx, "", "useradd", "--no-create-home", "--home-dir", home, "--shell", a.Shell, "--comment", name+"@"+strings.ToUpper(realm), name); err != nil {
		return err
	}
	undo := func(err error) error {
		a.Run(context.Background(), "", "userdel", name)
		os.RemoveAll(home)
		return err
	}
	uid, ok := a.Lookup(name)
	if !ok {
		return undo(errors.New("the new account cannot be found"))
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return undo(err)
	}
	if _, err := a.Run(ctx, "", "chown", name+":"+name, home); err != nil {
		return undo(err)
	}
	for _, g := range groups {
		a.Run(ctx, "", "usermod", "-aG", g, name)
	}
	recovery, err := a.Run(ctx, password+"\n", "sintykey", "provision", "--user", name, "--uid", uid, "--home", home)
	if err != nil {
		return undo(err)
	}
	if _, err := a.Run(ctx, "", "usermod", "-p", "*", name); err != nil {
		return undo(err)
	}
	if _, err := os.Stat(a.Skel); err == nil {
		a.Run(ctx, "", "cp", "-aT", a.Skel, home)
		a.Run(ctx, "", "chown", "-R", name+":"+name, home)
	}
	if err := os.MkdirAll(filepath.Dir(a.marker(name)), 0o700); err != nil {
		return undo(err)
	}
	return os.WriteFile(a.marker(name), []byte(strings.TrimSpace(recovery)+"\n"), 0o600)
}

func (a *Accounts) Lock(ctx context.Context, name string) error {
	if !a.Owned(name) {
		return nil
	}
	if _, err := a.Run(ctx, "", "usermod", "-L", name); err != nil {
		return err
	}
	return os.WriteFile(a.marker(name)+".locked", nil, 0o600)
}

func (a *Accounts) Unlock(ctx context.Context, name string) error {
	if _, err := os.Stat(a.marker(name) + ".locked"); err != nil {
		return nil
	}
	if _, err := a.Run(ctx, "", "usermod", "-p", "*", name); err != nil {
		return err
	}
	return os.Remove(a.marker(name) + ".locked")
}
