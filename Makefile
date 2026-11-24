PREFIX ?= /usr

.PHONY: all build release test vet install clean

all: build

build:
	go build -o sinty-domaind ./cmd/sinty-domaind
	go build -o sinty-domain ./cmd/sinty-domain

release:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o sinty-domaind ./cmd/sinty-domaind
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o sinty-domain ./cmd/sinty-domain

test:
	go test ./...

vet:
	go vet ./...

install: release
	install -Dm755 sinty-domaind $(DESTDIR)$(PREFIX)/libexec/sinty-domaind
	install -Dm755 sinty-domain $(DESTDIR)$(PREFIX)/bin/sinty-domain
	install -Dm644 packaging/sinty-domaind.service $(DESTDIR)$(PREFIX)/lib/systemd/system/sinty-domaind.service
	install -Dm644 packaging/sinty-domaind.conf $(DESTDIR)$(PREFIX)/share/dbus-1/system.d/sinty-domaind.conf
	install -Dm644 packaging/dev.sinty.Domain1.service $(DESTDIR)$(PREFIX)/share/dbus-1/system-services/dev.sinty.Domain1.service

clean:
	rm -f sinty-domaind sinty-domain
