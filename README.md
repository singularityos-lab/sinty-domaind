# sinty-domaind

Organisation accounts for Sinty OS. A device joins a Kerberos domain, such as
Active Directory, and people then sign in with their organisation's user name
and password. Kerberos is implemented here from the RFCs; no MIT, Heimdal,
SSSD or realmd code is used.

## Signing in

Online, the password is checked by the domain controller: an AS exchange with
encrypted-timestamp pre-authentication, AES256 or AES128 with HMAC-SHA1
(RFC 4120, 3961, 3962). The daemon then asks for a ticket to this device's own
`host/` principal and opens it with the device key. A controller that does not
know that key cannot produce the ticket, so a spoofed controller cannot accept
an arbitrary password.

After an online sign-in the device keeps a PBKDF2-SHA256 verifier of the
password (600 000 rounds, random salt, root-only file). Offline sign-in is
checked against it until the lease ends, seven days after the last online
sign-in by default. Five wrong passwords lock offline sign-in for a minute,
doubling up to an hour. A password changed elsewhere replaces the verifier at
the next online sign-in. An account the controller reports as disabled loses
its cached sign-in at once.

## Joining

The administrator creates the device account and gives the device its secret,
for example in a join token. `join` stores the domain, the device name, the
controllers and the secret in `/var/lib/sinty-domaind/join.json`, readable by
root only.

The organisation's network is recognised only when its directory answers over
TLS with the public key pinned at join time (`-pin`, the SHA-256 of the
SubjectPublicKeyInfo, which `sinty-domain pin HOST:636` prints). The daemon
then writes the UUID of the current connection to `/run/sinty-domaind/network`
and sinty-nm reports that network as `work`. A network name or a user choice
never makes a network a work network.

## D-Bus

Name `dev.sinty.Domain1`, object `/dev/sinty/Domain1`, interface
`dev.sinty.Domain1`.

| Member | Signature | |
| --- | --- | --- |
| `Status` | `() -> (b joined, s realm, s host, b work_network)` | anyone |
| `Join` | `(s realm, s host, s secret, as controllers, s directory, s pin)` | root |
| `Login` | `(s user, s password) -> (b offline, x lease_end)` | root |
| `Leave` | `()` | root, forgets every cached sign-in |

Failures are `dev.sinty.Domain1.Error.` followed by `Wrong`, `Disabled`,
`Expired`, `Locked`, `NeedsNetwork`, `Untrusted`, `NotJoined`, `NotAllowed` or
`Failed`.

## Command line

```sh
sinty-domain status
sinty-domain pin dc.example.com:636
echo "$SECRET" | sinty-domain join -realm EXAMPLE.COM -host pc1.example.com -kdc dc.example.com -pin 3f2a...
echo "$PASSWORD" | sinty-domain login alice
sinty-domain leave
```

## Tests

`go test ./...` runs everything that needs no network, including the RFC 3961
and 3962 test vectors. With `KRB_TEST_KDC=host:port` pointing at a controller
for `EXAMPLE.TEST` that has the accounts the tests expect, the sign-in tests
run against it as well.
