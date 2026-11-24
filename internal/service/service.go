// Package service exports dev.sinty.Domain1 on the system bus. Only root may
// call it: the login service asks it to check a password, the Settings helper
// to join or leave.
package service

import (
	"context"
	"errors"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"

	"github.com/singularityos-lab/sinty-domaind/internal/domain"
)

const (
	Name  = "dev.sinty.Domain1"
	Path  = dbus.ObjectPath("/dev/sinty/Domain1")
	Iface = "dev.sinty.Domain1"
)

type Service struct {
	D      *domain.Domain
	Work   func() bool
	Caller func(sender dbus.Sender) (uint32, error)
}

func dbusErr(name string, err error) *dbus.Error {
	return dbus.NewError(Iface+".Error."+name, []any{err.Error()})
}

func (s *Service) root(sender dbus.Sender) *dbus.Error {
	uid, err := s.Caller(sender)
	if err != nil || uid != 0 {
		return dbusErr("NotAllowed", errors.New("only the system may do this"))
	}
	return nil
}

func (s *Service) Status() (bool, string, string, bool, *dbus.Error) {
	j, err := s.D.Joined()
	if err != nil {
		return false, "", "", false, nil
	}
	return true, j.Realm, j.Host, s.Work != nil && s.Work(), nil
}

func (s *Service) Join(sender dbus.Sender, realm, host, secret string, kdcs []string, directory, pin string) *dbus.Error {
	if e := s.root(sender); e != nil {
		return e
	}
	err := s.D.Join(context.Background(), domain.Join{Realm: realm, Host: host, Machine: secret, KDCs: kdcs, Directory: directory, CertPin: pin})
	if err != nil {
		return dbusErr("Failed", err)
	}
	return nil
}

func (s *Service) Leave(sender dbus.Sender) *dbus.Error {
	if e := s.root(sender); e != nil {
		return e
	}
	if err := s.D.Leave(); err != nil {
		return dbusErr("Failed", err)
	}
	return nil
}

func (s *Service) Login(sender dbus.Sender, user, password string) (bool, int64, *dbus.Error) {
	if e := s.root(sender); e != nil {
		return false, 0, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := s.D.Login(ctx, user, password)
	if err != nil {
		name := "Failed"
		switch {
		case errors.Is(err, domain.ErrWrong):
			name = "Wrong"
		case errors.Is(err, domain.ErrDisabled):
			name = "Disabled"
		case errors.Is(err, domain.ErrExpired):
			name = "Expired"
		case errors.Is(err, domain.ErrLocked):
			name = "Locked"
		case errors.Is(err, domain.ErrOfflineStale), errors.Is(err, domain.ErrUnknownUser):
			name = "NeedsNetwork"
		case errors.Is(err, domain.ErrSpoofed):
			name = "Untrusted"
		case errors.Is(err, domain.ErrNotJoined):
			name = "NotJoined"
		}
		return false, 0, dbusErr(name, err)
	}
	return r.Offline, r.Until.Unix(), nil
}

func Export(conn *dbus.Conn, s *Service) error {
	if s.Caller == nil {
		s.Caller = func(sender dbus.Sender) (uint32, error) {
			var uid uint32
			err := conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixUser", 0, string(sender)).Store(&uid)
			return uid, err
		}
	}
	if err := conn.Export(s, Path, Iface); err != nil {
		return err
	}
	node := &introspect.Node{Name: string(Path), Interfaces: []introspect.Interface{introspect.IntrospectData, {Name: Iface, Methods: introspect.Methods(s)}}}
	return conn.Export(introspect.NewIntrospectable(node), Path, "org.freedesktop.DBus.Introspectable")
}
