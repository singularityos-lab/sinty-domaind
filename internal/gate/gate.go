// Package gate is the socket the sign-in module asks whether a domain user may
// sign in. Only root may connect: the module runs inside the login service.
package gate

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/singularityos-lab/sinty-domaind/internal/account"
	"github.com/singularityos-lab/sinty-domaind/internal/domain"
)

const Socket = "/run/sinty-domaind.sock"

type Gate struct {
	D        *domain.Domain
	Accounts *account.Accounts
	Peer     func(c *net.UnixConn) (uint32, error)
}

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var cerr error
	raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if cerr != nil {
		return 0, cerr
	}
	return cred.Uid, nil
}

func Listen(path string) (*net.UnixListener, error) {
	os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func (g *Gate) Serve(ln *net.UnixListener) error {
	if g.Peer == nil {
		g.Peer = peerUID
	}
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go g.handle(c)
	}
}

func reason(err error) string {
	switch {
	case errors.Is(err, domain.ErrWrong):
		return "Wrong"
	case errors.Is(err, domain.ErrDisabled):
		return "Disabled"
	case errors.Is(err, domain.ErrExpired):
		return "Expired"
	case errors.Is(err, domain.ErrOfflineStale), errors.Is(err, domain.ErrUnknownUser):
		return "NeedsNetwork"
	case errors.Is(err, domain.ErrSpoofed):
		return "Untrusted"
	case errors.Is(err, domain.ErrNotJoined):
		return "NotJoined"
	case errors.Is(err, account.ErrConflict):
		return "Conflict"
	}
	return "Failed"
}

func (g *Gate) handle(c *net.UnixConn) {
	defer c.Close()
	if uid, err := g.Peer(c); err != nil || uid != 0 {
		return
	}
	c.SetDeadline(time.Now().Add(60 * time.Second))
	r := bufio.NewReader(io.LimitReader(c, 1024))
	if verb, err := r.ReadString('\n'); err != nil || verb != "login\n" {
		return
	}
	name, _ := r.ReadString('\n')
	password, err := r.ReadString('\n')
	if err != nil {
		return
	}
	name = strings.TrimSuffix(name, "\n")
	password = strings.TrimSuffix(password, "\n")
	io.WriteString(c, g.Login(context.Background(), name, password)+"\n")
}

func (g *Gate) Login(ctx context.Context, name, password string) string {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	res, err := g.D.Login(ctx, name, password)
	if errors.Is(err, domain.ErrDisabled) {
		if lerr := g.Accounts.Lock(ctx, name); lerr != nil {
			log.Printf("lock %s: %v", name, lerr)
		}
	}
	if err != nil {
		return "ERR " + reason(err)
	}
	if res.Offline {
		if !g.Accounts.Owned(name) {
			return "ERR NeedsNetwork"
		}
		return "OK offline"
	}
	if err := g.Accounts.Ensure(ctx, name, mustRealm(g.D), password); err != nil {
		log.Printf("account for %s: %v", name, err)
		return "ERR " + reason(err)
	}
	if err := g.Accounts.Unlock(ctx, name); err != nil {
		log.Printf("unlock %s: %v", name, err)
	}
	return "OK online"
}

func mustRealm(d *domain.Domain) string {
	j, _ := d.Joined()
	return j.Realm
}
