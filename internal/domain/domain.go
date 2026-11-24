// Package domain signs people in with their organisation's account: online
// against the domain controller, offline against what the last online sign-in
// left on this device.
package domain

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
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

const (
	verifierRounds = 600000
	freeAttempts   = 5
	maxLockout     = time.Hour
)

var (
	ErrNotJoined    = errors.New("this device has not joined a domain")
	ErrWrong        = errors.New("wrong user name or password")
	ErrDisabled     = errors.New("this account is disabled")
	ErrExpired      = errors.New("the password has expired, change it on a device connected to the domain")
	ErrLocked       = errors.New("too many attempts, try again later")
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

type cached struct {
	Salt     []byte    `json:"salt"`
	Verifier []byte    `json:"verifier"`
	Until    time.Time `json:"until"`
	Failures int       `json:"failures"`
	Locked   time.Time `json:"locked"`
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
	var c cached
	hasCache := readJSON(d.userPath(user), &c) == nil
	now := d.Now()
	if hasCache && now.Before(c.Locked) {
		return Result{}, ErrLocked
	}
	err = d.online(ctx, j, user, password)
	switch {
	case err == nil:
		c, err := d.remember(user, password, j.Lease)
		if err != nil {
			return Result{}, err
		}
		return Result{User: user, Until: c.Until}, nil
	case errors.Is(err, ErrDisabled):
		os.Remove(d.userPath(user))
		return Result{}, err
	case errors.Is(err, ErrWrong):
		if hasCache {
			d.fail(user, c)
		}
		return Result{}, err
	case errors.Is(err, ErrExpired), errors.Is(err, ErrSpoofed):
		return Result{}, err
	}
	if !unreachable(err) {
		return Result{}, err
	}
	if !hasCache {
		return Result{}, ErrUnknownUser
	}
	if !now.Before(c.Until) {
		return Result{}, ErrOfflineStale
	}
	got := pbkdf2Verifier(password, c.Salt)
	if !hmac.Equal(got, c.Verifier) {
		d.fail(user, c)
		return Result{}, ErrWrong
	}
	c.Failures = 0
	c.Locked = time.Time{}
	writeJSON(d.userPath(user), c)
	return Result{User: user, Offline: true, Until: c.Until}, nil
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

func pbkdf2Verifier(password string, salt []byte) []byte {
	v, _ := pbkdf2.Key(sha256.New, password, salt, verifierRounds, 32)
	return v
}

func (d *Domain) remember(user, password string, lease time.Duration) (cached, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return cached{}, err
	}
	c := cached{Salt: salt, Verifier: pbkdf2Verifier(password, salt), Until: d.Now().Add(lease).UTC()}
	return c, writeJSON(d.userPath(user), c)
}

func (d *Domain) fail(user string, c cached) {
	c.Failures++
	if c.Failures >= freeAttempts {
		wait := time.Minute << (c.Failures - freeAttempts)
		if wait <= 0 || wait > maxLockout {
			wait = maxLockout
		}
		c.Locked = d.Now().Add(wait)
	}
	writeJSON(d.userPath(user), c)
}
