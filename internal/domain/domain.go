// Package domain checks organisation accounts against the domain controller
// and keeps the lease that allows signing in without it. Offline, the password
// itself is checked by the seal of the user's home, which the TPM throttles.
package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/singularityos-lab/sinty-domaind/internal/krb"
)

var (
	ErrNotJoined    = errors.New("this device has not joined a domain")
	ErrWrong        = errors.New("wrong user name or password")
	ErrDisabled     = errors.New("this account is disabled")
	ErrExpired      = errors.New("the password has expired, change it on a device connected to the domain")
	ErrOfflineStale = errors.New("connect to the organisation's network to sign in again")
	ErrUnknownUser  = errors.New("this account has never signed in on this device, connect to the organisation's network")
	ErrSpoofed      = errors.New("the domain controller could not prove who it is")
	validUser       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type Join struct {
	Realm     string        `json:"realm"`
	Host      string        `json:"host"`
	KDCs      []string      `json:"kdcs,omitempty"`
	Machine   string        `json:"machine"`
	Salt      string        `json:"salt,omitempty"`
	Lease     time.Duration `json:"lease"`
	CertPin   string        `json:"cert_pin,omitempty"`
	Directory string        `json:"directory,omitempty"`
	JoinedAt  time.Time     `json:"joined_at"`
}

func (j Join) machineSalt() string {
	if j.Salt != "" {
		return j.Salt
	}
	return strings.ToUpper(j.Realm) + "host" + strings.ToLower(j.Host)
}

type lease struct {
	Until time.Time `json:"until"`
}

type Result struct {
	User    string
	Offline bool
	Until   time.Time
}

type KDC interface {
	Login(ctx context.Context, user, password string) (*krb.TGT, error)
	Service(ctx context.Context, tgt *krb.TGT, service krb.PrincipalName) (*krb.ServiceTicket, error)
}

type Domain struct {
	Dir  string
	Now  func() time.Time
	Dial func(j Join) KDC
	mu   sync.Mutex
}

func New(dir string) *Domain {
	return &Domain{Dir: dir, Now: time.Now, Dial: func(j Join) KDC {
		return &krb.Client{Realm: strings.ToUpper(j.Realm), KDCs: j.KDCs}
	}}
}

func (d *Domain) joinPath() string { return filepath.Join(d.Dir, "join.json") }

func (d *Domain) userPath(user string) string {
	return filepath.Join(d.Dir, "users", strings.ToLower(user)+".json")
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (d *Domain) Joined() (Join, error) {
	var j Join
	if err := readJSON(d.joinPath(), &j); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return j, ErrNotJoined
		}
		return j, err
	}
	return j, nil
}

func (d *Domain) Join(ctx context.Context, j Join) error {
	if j.Realm == "" || j.Host == "" || j.Machine == "" {
		return errors.New("a domain, a device name and its secret are needed to join")
	}
	if j.Lease == 0 {
		j.Lease = 7 * 24 * time.Hour
	}
	j.JoinedAt = d.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()
	return writeJSON(d.joinPath(), j)
}

func (d *Domain) Leave() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.RemoveAll(filepath.Join(d.Dir, "users")); err != nil {
		return err
	}
	if err := os.Remove(d.joinPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func unreachable(err error) bool {
	var ne net.Error
	var oe *net.OpError
	return errors.As(err, &ne) || errors.As(err, &oe) || strings.Contains(err.Error(), "no domain controller")
}

func (d *Domain) Login(ctx context.Context, user, password string) (Result, error) {
	if !validUser.MatchString(user) {
		return Result{}, ErrWrong
	}
	j, err := d.Joined()
	if err != nil {
		return Result{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var l lease
	known := readJSON(d.userPath(user), &l) == nil
	err = d.online(ctx, j, user, password)
	switch {
	case err == nil:
		l = lease{Until: d.Now().Add(j.Lease).UTC()}
		if err := writeJSON(d.userPath(user), l); err != nil {
			return Result{}, err
		}
		return Result{User: user, Until: l.Until}, nil
	case errors.Is(err, ErrDisabled):
		os.Remove(d.userPath(user))
		return Result{}, err
	case errors.Is(err, ErrWrong), errors.Is(err, ErrExpired), errors.Is(err, ErrSpoofed):
		return Result{}, err
	}
	if !unreachable(err) {
		return Result{}, err
	}
	if !known {
		return Result{}, ErrUnknownUser
	}
	if !d.Now().Before(l.Until) {
		return Result{}, ErrOfflineStale
	}
	return Result{User: user, Offline: true, Until: l.Until}, nil
}

func (d *Domain) online(ctx context.Context, j Join, user, password string) error {
	kdc := d.Dial(j)
	tgt, err := kdc.Login(ctx, user, password)
	if err != nil {
		var ke *krb.Error
		if errors.As(err, &ke) {
			switch ke.Code {
			case krb.ErrPreauthFailed, krb.ErrPrincipalUnknown:
				return ErrWrong
			case krb.ErrClientRevoked:
				return ErrDisabled
			case krb.ErrKeyExpired:
				return ErrExpired
			}
			return err
		}
		if errors.Is(err, krb.ErrIntegrity) {
			return ErrWrong
		}
		return err
	}
	host := krb.Principal(krb.NameTypeHost, "host", strings.ToLower(j.Host))
	st, err := kdc.Service(ctx, tgt, host)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSpoofed, err)
	}
	key, err := ticketKey(st, j)
	if err != nil {
		return ErrSpoofed
	}
	realm, who, err := krb.OpenTicket(st.Ticket, key)
	if err != nil || !strings.EqualFold(realm, j.Realm) || who.String() != user {
		return ErrSpoofed
	}
	return nil
}

func ticketKey(st *krb.ServiceTicket, j Join) (krb.Key, error) {
	etype, err := krb.TicketEType(st.Ticket)
	if err != nil {
		return krb.Key{}, err
	}
	return krb.StringToKey(etype, j.Machine, j.machineSalt(), 0)
}
