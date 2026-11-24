package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-domaind/internal/domain"
	"github.com/singularityos-lab/sinty-domaind/internal/service"
	"github.com/singularityos-lab/sinty-domaind/internal/worknet"
)

func primaryConnection(conn *dbus.Conn) string {
	nm := conn.Object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
	v, err := nm.GetProperty("org.freedesktop.NetworkManager.PrimaryConnection")
	if err != nil {
		return ""
	}
	path, ok := v.Value().(dbus.ObjectPath)
	if !ok || path == "/" {
		return ""
	}
	u, err := conn.Object("org.freedesktop.NetworkManager", path).GetProperty("org.freedesktop.NetworkManager.Connection.Active.Uuid")
	if err != nil {
		return ""
	}
	s, _ := u.Value().(string)
	return s
}

func directory(j domain.Join) string {
	if j.Directory != "" {
		return j.Directory
	}
	if len(j.KDCs) > 0 {
		host := j.KDCs[0]
		if i := strings.LastIndex(host, ":"); i > 0 && !strings.HasSuffix(host, "]") {
			host = host[:i]
		}
		return host + ":636"
	}
	return "ldap." + strings.ToLower(j.Realm) + ":636"
}

func main() {
	state := flag.String("state", "/var/lib/sinty-domaind", "where the domain membership and cached sign-ins are kept")
	flag.Parse()
	log.SetFlags(0)
	d := domain.New(*state)
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		log.Fatalf("system bus: %v", err)
	}
	defer conn.Close()
	var work atomic.Bool
	svc := &service.Service{D: d, Work: work.Load}
	if err := service.Export(conn, svc); err != nil {
		log.Fatalf("export: %v", err)
	}
	reply, err := conn.RequestName(service.Name, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("cannot own %s: %v", service.Name, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		last := ""
		for {
			current := ""
			if j, err := d.Joined(); err == nil && j.CertPin != "" {
				if uuid := primaryConnection(conn); uuid != "" {
					vctx, vcancel := context.WithTimeout(ctx, 10*time.Second)
					if worknet.Verify(vctx, directory(j), j.CertPin) {
						current = uuid
					}
					vcancel()
				}
			}
			work.Store(current != "")
			if current != last {
				if err := worknet.Publish(worknet.Dir, current); err != nil {
					log.Printf("work network: %v", err)
				}
				last = current
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
