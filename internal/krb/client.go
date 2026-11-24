package krb

import (
	"context"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"
)

type Client struct {
	Realm   string
	KDCs    []string
	Timeout time.Duration
	Now     func() time.Time
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
}

type TGT struct {
	Realm      string
	User       PrincipalName
	Ticket     []byte
	SessionKey Key
	End        time.Time
}

type ServiceTicket struct {
	Service    PrincipalName
	Ticket     []byte
	SessionKey Key
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) kdcs() ([]string, error) {
	if len(c.KDCs) > 0 {
		return c.KDCs, nil
	}
	_, srvs, err := net.LookupSRV("kerberos", "tcp", strings.ToLower(c.Realm))
	if err != nil {
		return nil, fmt.Errorf("krb: no domain controller for %s: %w", c.Realm, err)
	}
	var out []string
	for _, s := range srvs {
		out = append(out, net.JoinHostPort(strings.TrimSuffix(s.Target, "."), fmt.Sprint(s.Port)))
	}
	return out, nil
}

func (c *Client) exchange(ctx context.Context, msg []byte) ([]byte, error) {
	kdcs, err := c.kdcs()
	if err != nil {
		return nil, err
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dial := c.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	var last error
	for _, addr := range kdcs {
		if !strings.Contains(addr, ":") || strings.Count(addr, ":") > 1 && !strings.HasPrefix(addr, "[") {
			addr = net.JoinHostPort(addr, "88")
		}
		reply, err := func() ([]byte, error) {
			dctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			conn, err := dial(dctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(timeout))
			if _, err := conn.Write(binary.BigEndian.AppendUint32(nil, uint32(len(msg)))); err != nil {
				return nil, err
			}
			if _, err := conn.Write(msg); err != nil {
				return nil, err
			}
			var head [4]byte
			if _, err := io.ReadFull(conn, head[:]); err != nil {
				return nil, err
			}
			n := binary.BigEndian.Uint32(head[:])
			if n > 1<<20 {
				return nil, errors.New("krb: reply too large")
			}
			reply := make([]byte, n)
			_, err = io.ReadFull(conn, reply)
			return reply, err
		}()
		if err == nil {
			return reply, nil
		}
		last = err
	}
	return nil, fmt.Errorf("krb: no domain controller answered: %w", last)
}

func nonce() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<31-1))
	return int(n.Int64())
}

func options() asn1.BitString {
	return asn1.BitString{Bytes: []byte{0x40, 0x00, 0x00, 0x10}, BitLength: 32}
}

func (c *Client) asReq(user PrincipalName, pa []paData, n int) ([]byte, error) {
	body, err := asn1.Marshal(kdcReqBody{
		Options: options(),
		CName:   user,
		Realm:   explicitString(2, c.Realm),
		SName:   Principal(NameTypeService, "krbtgt", c.Realm),
		Till:    kerberosTime(c.now().Add(24 * time.Hour)),
		Nonce:   n,
		ETypes:  []int32{AES256, AES128},
	})
	if err != nil {
		return nil, err
	}
	return wrap(msgASReq, kdcReq{PVNO: pvno, MsgType: msgASReq, PAData: pa, Body: explicit(4, body)})
}

type saltInfo struct {
	etype int32
	salt  string
	iter  int
}

func pickSalt(edata []byte, realm string, user PrincipalName) (saltInfo, error) {
	info := saltInfo{etype: AES256, salt: realm + strings.Join(user.Parts(), "")}
	var methods []paData
	if _, err := asn1.Unmarshal(edata, &methods); err != nil {
		return info, nil
	}
	for _, m := range methods {
		if m.Type != paETypeInfo {
			continue
		}
		var entries []etypeInfo2Entry
		if _, err := asn1.Unmarshal(m.Value, &entries); err != nil {
			return info, err
		}
		for _, e := range entries {
			if e.EType != AES256 && e.EType != AES128 {
				continue
			}
			info.etype = e.EType
			if salt := text(e.Salt); salt != "" {
				info.salt = salt
			}
			if len(e.Params) == 4 {
				info.iter = int(binary.BigEndian.Uint32(e.Params))
			}
			return info, nil
		}
		return info, errors.New("krb: the domain offers no AES key for this user")
	}
	return info, nil
}

func (c *Client) Login(ctx context.Context, user, password string) (*TGT, error) {
	cname := Principal(NameTypePrincipal, user)
	n := nonce()
	req, err := c.asReq(cname, nil, n)
	if err != nil {
		return nil, err
	}
	reply, err := c.exchange(ctx, req)
	if err != nil {
		return nil, err
	}
	info := saltInfo{etype: AES256, salt: c.Realm + user}
	tag, inner, err := application(reply)
	if err != nil {
		return nil, err
	}
	if tag == msgError {
		kerr := parseError(inner)
		var e *Error
		if !errors.As(kerr, &e) || e.Code != ErrPreauthRequired {
			return nil, kerr
		}
		if info, err = pickSalt(e.data, c.Realm, cname); err != nil {
			return nil, err
		}
	}
	if info.iter > 1<<22 {
		return nil, errors.New("krb: unreasonable key iteration count")
	}
	key, err := StringToKey(info.etype, password, info.salt, info.iter)
	if err != nil {
		return nil, err
	}
	now := c.now().UTC()
	ts, err := asn1.Marshal(paEncTSEnc{Time: kerberosTime(now), Usec: now.Nanosecond() / 1000})
	if err != nil {
		return nil, err
	}
	sealed, err := Encrypt(key, usageEncTimestamp, ts)
	if err != nil {
		return nil, err
	}
	pa, err := asn1.Marshal(encryptedData{EType: key.Type, Cipher: sealed})
	if err != nil {
		return nil, err
	}
	n = nonce()
	if req, err = c.asReq(cname, []paData{{Type: paEncTime, Value: pa}}, n); err != nil {
		return nil, err
	}
	if reply, err = c.exchange(ctx, req); err != nil {
		return nil, err
	}
	rep, part, err := c.openReply(reply, msgASRep, key, usageASRepPart, n)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(text(rep.CRealm), c.Realm) || rep.CName.String() != user {
		return nil, errors.New("krb: the reply is for someone else")
	}
	return &TGT{
		Realm:      text(rep.CRealm),
		User:       rep.CName,
		Ticket:     rep.Ticket.Bytes,
		SessionKey: Key{Type: part.Key.Type, Value: part.Key.Value},
		End:        part.EndTime,
	}, nil
}

func (c *Client) openReply(reply []byte, want int, key Key, usage uint32, n int) (kdcRep, encKDCRepPart, error) {
	var rep kdcRep
	var part encKDCRepPart
	tag, inner, err := application(reply)
	if err != nil {
		return rep, part, err
	}
	if tag == msgError {
		return rep, part, parseError(inner)
	}
	if tag != want {
		return rep, part, fmt.Errorf("krb: unexpected reply %d", tag)
	}
	if _, err := asn1.Unmarshal(inner, &rep); err != nil {
		return rep, part, err
	}
	if rep.EncPart.EType != key.Type {
		return rep, part, errors.New("krb: reply sealed with an unexpected key type")
	}
	plain, err := Decrypt(key, usage, rep.EncPart.Cipher)
	if err != nil {
		return rep, part, err
	}
	ptag, pinner, err := application(plain)
	if err != nil {
		return rep, part, err
	}
	if ptag != tagEncAS && ptag != tagEncTGS {
		return rep, part, fmt.Errorf("krb: unexpected sealed part %d", ptag)
	}
	if _, err := asn1.Unmarshal(pinner, &part); err != nil {
		return rep, part, err
	}
	if part.Nonce != n {
		return rep, part, errors.New("krb: the reply does not answer this request")
	}
	return rep, part, nil
}

func (c *Client) Service(ctx context.Context, tgt *TGT, service PrincipalName) (*ServiceTicket, error) {
	n := nonce()
	body, err := asn1.Marshal(kdcReqBody{
		Options: options(),
		Realm:   explicitString(2, tgt.Realm),
		SName:   service,
		Till:    kerberosTime(c.now().Add(10 * time.Hour)),
		Nonce:   n,
		ETypes:  []int32{AES256, AES128},
	})
	if err != nil {
		return nil, err
	}
	sum, err := Checksum(tgt.SessionKey, usageReqChecksum, body)
	if err != nil {
		return nil, err
	}
	now := c.now().UTC()
	auth, err := wrap(tagAuth, authenticator{
		VNO: pvno, Realm: explicitString(1, tgt.Realm), CName: tgt.User,
		Checksum: checksum{Type: checksumType(tgt.SessionKey.Type), Value: sum},
		CUsec:    now.Nanosecond() / 1000, CTime: kerberosTime(now),
	})
	if err != nil {
		return nil, err
	}
	sealed, err := Encrypt(tgt.SessionKey, usageAuthenticator, auth)
	if err != nil {
		return nil, err
	}
	ap, err := wrap(msgAPReq, apReq{
		PVNO: pvno, MsgType: msgAPReq, Options: asn1.BitString{Bytes: []byte{0, 0, 0, 0}, BitLength: 32},
		Ticket:        explicit(3, tgt.Ticket),
		Authenticator: encryptedData{EType: tgt.SessionKey.Type, Cipher: sealed},
	})
	if err != nil {
		return nil, err
	}
	req, err := wrap(msgTGSReq, kdcReq{PVNO: pvno, MsgType: msgTGSReq, PAData: []paData{{Type: paTGSReq, Value: ap}}, Body: explicit(4, body)})
	if err != nil {
		return nil, err
	}
	reply, err := c.exchange(ctx, req)
	if err != nil {
		return nil, err
	}
	rep, part, err := c.openReply(reply, msgTGSRep, tgt.SessionKey, usageTGSRepPart, n)
	if err != nil {
		return nil, err
	}
	return &ServiceTicket{Service: part.SName, Ticket: rep.Ticket.Bytes, SessionKey: Key{Type: part.Key.Type, Value: part.Key.Value}}, nil
}

func OpenTicket(raw []byte, serviceKey Key) (realm string, user PrincipalName, err error) {
	tag, inner, err := application(raw)
	if err != nil {
		return "", user, err
	}
	if tag != tagTicket {
		return "", user, errors.New("krb: not a ticket")
	}
	var t ticket
	if _, err := asn1.Unmarshal(inner, &t); err != nil {
		return "", user, err
	}
	if t.EncPart.EType != serviceKey.Type {
		return "", user, errors.New("krb: ticket sealed with another key type")
	}
	plain, err := Decrypt(serviceKey, usageTicket, t.EncPart.Cipher)
	if err != nil {
		return "", user, err
	}
	ptag, pinner, err := application(plain)
	if err != nil || ptag != tagEncTkt {
		return "", user, errors.New("krb: unreadable ticket")
	}
	var part encTicketPart
	if _, err := asn1.Unmarshal(pinner, &part); err != nil {
		return "", user, err
	}
	return text(part.CRealm), part.CName, nil
}

func TicketEType(raw []byte) (int32, error) {
	tag, inner, err := application(raw)
	if err != nil {
		return 0, err
	}
	if tag != tagTicket {
		return 0, errors.New("krb: not a ticket")
	}
	var t ticket
	if _, err := asn1.Unmarshal(inner, &t); err != nil {
		return 0, err
	}
	return t.EncPart.EType, nil
}
