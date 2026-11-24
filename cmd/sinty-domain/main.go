package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-domaind/internal/worknet"
)

const (
	name  = "dev.sinty.Domain1"
	path  = "/dev/sinty/Domain1"
	iface = "dev.sinty.Domain1"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  sinty-domain status
  sinty-domain pin HOST:636
  sinty-domain join -realm REALM -host NAME [-kdc HOST[:PORT]]... [-directory HOST:636] [-pin SHA256]   (device secret on standard input)
  sinty-domain leave`)
	os.Exit(2)
}

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func readLine() string {
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sinty-domain:", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	if os.Args[1] == "pin" {
		if len(os.Args) != 3 {
			usage()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pin, err := worknet.Fetch(ctx, os.Args[2])
		if err != nil {
			fail(err)
		}
		fmt.Println(pin)
		return
	}
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		fail(err)
	}
	obj := conn.Object(name, path)
	switch os.Args[1] {
	case "status":
		var joined, work bool
		var realm, host string
		if err := obj.Call(iface+".Status", 0).Store(&joined, &realm, &host, &work); err != nil {
			fail(err)
		}
		if !joined {
			fmt.Println("not joined")
			return
		}
		fmt.Printf("joined %s as %s, organisation network: %v\n", realm, host, work)
	case "join":
		fs := flag.NewFlagSet("join", flag.ExitOnError)
		realm := fs.String("realm", "", "domain name")
		host := fs.String("host", "", "this device's name in the domain")
		dir := fs.String("directory", "", "directory address checked to recognise the organisation's network")
		pin := fs.String("pin", "", "SHA-256 of the directory's public key")
		var kdcs list
		fs.Var(&kdcs, "kdc", "domain controller, repeatable")
		fs.Parse(os.Args[2:])
		secret := readLine()
		if err := obj.Call(iface+".Join", 0, *realm, *host, secret, []string(kdcs), *dir, *pin).Err; err != nil {
			fail(err)
		}
		fmt.Println("joined")
	case "leave":
		if err := obj.Call(iface+".Leave", 0).Err; err != nil {
			fail(err)
		}
		fmt.Println("left the domain")
	default:
		usage()
	}
}
