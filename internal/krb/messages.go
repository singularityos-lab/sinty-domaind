package krb

import (
	"encoding/asn1"
	"fmt"
	"strings"
	"time"
)

const (
	pvno        = 5
	msgASReq    = 10
	msgASRep    = 11
	msgTGSReq   = 12
	msgTGSRep   = 13
	msgAPReq    = 14
	msgError    = 30
	tagTicket   = 1
	tagAuth     = 2
	tagEncAS    = 25
	tagEncTGS   = 26
	tagEncTkt   = 3
	paTGSReq    = 1
	paEncTime   = 2
	paETypeInfo = 19

	NameTypePrincipal = 1
	NameTypeService   = 2
	NameTypeHost      = 3
)

func gstring(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: 27, Bytes: []byte(s)}
}

func explicit(tag int, inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner}
}

func explicitString(tag int, s string) asn1.RawValue {
	inner, _ := asn1.Marshal(gstring(s))
	return explicit(tag, inner)
}

func text(rv asn1.RawValue) string {
	if rv.Class == asn1.ClassContextSpecific {
		var inner asn1.RawValue
		if _, err := asn1.Unmarshal(rv.Bytes, &inner); err == nil {
			return string(inner.Bytes)
		}
	}
	return string(rv.Bytes)
}

type PrincipalName struct {
	NameType   int32           `asn1:"explicit,tag:0"`
	NameString []asn1.RawValue `asn1:"explicit,tag:1"`
}

func Principal(nameType int32, parts ...string) PrincipalName {
	p := PrincipalName{NameType: nameType}
	for _, s := range parts {
		p.NameString = append(p.NameString, gstring(s))
	}
	return p
}

func (p PrincipalName) Parts() []string {
	out := make([]string, len(p.NameString))
	for i, r := range p.NameString {
		out[i] = string(r.Bytes)
	}
	return out
}

func (p PrincipalName) String() string { return strings.Join(p.Parts(), "/") }

type paData struct {
	Type  int32  `asn1:"explicit,tag:1"`
	Value []byte `asn1:"explicit,tag:2"`
}

type encryptedData struct {
	EType  int32  `asn1:"explicit,tag:0"`
	KVNO   int    `asn1:"optional,explicit,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

type encryptionKey struct {
	Type  int32  `asn1:"explicit,tag:0"`
	Value []byte `asn1:"explicit,tag:1"`
}

type paEncTSEnc struct {
	Time time.Time `asn1:"generalized,explicit,tag:0"`
	Usec int       `asn1:"explicit,tag:1"`
}

type etypeInfo2Entry struct {
	EType  int32         `asn1:"explicit,tag:0"`
	Salt   asn1.RawValue `asn1:"optional,explicit,tag:1"`
	Params []byte        `asn1:"optional,explicit,tag:2"`
}

type kdcReqBody struct {
	Options asn1.BitString `asn1:"explicit,tag:0"`
	CName   PrincipalName  `asn1:"optional,explicit,tag:1"`
	Realm   asn1.RawValue  `asn1:"explicit,tag:2"`
	SName   PrincipalName  `asn1:"optional,explicit,tag:3"`
	Till    time.Time      `asn1:"generalized,explicit,tag:5"`
	Nonce   int            `asn1:"explicit,tag:7"`
	ETypes  []int32        `asn1:"explicit,tag:8"`
}

type kdcReq struct {
	PVNO    int           `asn1:"explicit,tag:1"`
	MsgType int           `asn1:"explicit,tag:2"`
	PAData  []paData      `asn1:"optional,explicit,tag:3"`
	Body    asn1.RawValue `asn1:"explicit,tag:4"`
}

type kdcRep struct {
	PVNO    int           `asn1:"explicit,tag:0"`
	MsgType int           `asn1:"explicit,tag:1"`
	PAData  []paData      `asn1:"optional,explicit,tag:2"`
	CRealm  asn1.RawValue `asn1:"explicit,tag:3"`
	CName   PrincipalName `asn1:"explicit,tag:4"`
	Ticket  asn1.RawValue `asn1:"explicit,tag:5"`
	EncPart encryptedData `asn1:"explicit,tag:6"`
}

type ticket struct {
	TktVNO  int           `asn1:"explicit,tag:0"`
	Realm   asn1.RawValue `asn1:"explicit,tag:1"`
	SName   PrincipalName `asn1:"explicit,tag:2"`
	EncPart encryptedData `asn1:"explicit,tag:3"`
}

type lastReq struct {
	Type  int32     `asn1:"explicit,tag:0"`
	Value time.Time `asn1:"generalized,explicit,tag:1"`
}

type encKDCRepPart struct {
	Key       encryptionKey  `asn1:"explicit,tag:0"`
	LastReq   []lastReq      `asn1:"explicit,tag:1"`
	Nonce     int            `asn1:"explicit,tag:2"`
	KeyExp    time.Time      `asn1:"generalized,optional,explicit,tag:3"`
	Flags     asn1.BitString `asn1:"explicit,tag:4"`
	AuthTime  time.Time      `asn1:"generalized,explicit,tag:5"`
	StartTime time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	EndTime   time.Time      `asn1:"generalized,explicit,tag:7"`
	RenewTill time.Time      `asn1:"generalized,optional,explicit,tag:8"`
	SRealm    asn1.RawValue  `asn1:"explicit,tag:9"`
	SName     PrincipalName  `asn1:"explicit,tag:10"`
}

type krbError struct {
	PVNO    int           `asn1:"explicit,tag:0"`
	MsgType int           `asn1:"explicit,tag:1"`
	CTime   time.Time     `asn1:"generalized,optional,explicit,tag:2"`
	CUsec   int           `asn1:"optional,explicit,tag:3"`
	STime   time.Time     `asn1:"generalized,explicit,tag:4"`
	SUsec   int           `asn1:"explicit,tag:5"`
	Code    int32         `asn1:"explicit,tag:6"`
	CRealm  asn1.RawValue `asn1:"optional,explicit,tag:7"`
	CName   PrincipalName `asn1:"optional,explicit,tag:8"`
	Realm   asn1.RawValue `asn1:"explicit,tag:9"`
	SName   PrincipalName `asn1:"explicit,tag:10"`
	EText   asn1.RawValue `asn1:"optional,explicit,tag:11"`
	EData   []byte        `asn1:"optional,explicit,tag:12"`
}

type apReq struct {
	PVNO          int            `asn1:"explicit,tag:0"`
	MsgType       int            `asn1:"explicit,tag:1"`
	Options       asn1.BitString `asn1:"explicit,tag:2"`
	Ticket        asn1.RawValue  `asn1:"explicit,tag:3"`
	Authenticator encryptedData  `asn1:"explicit,tag:4"`
}

type checksum struct {
	Type  int32  `asn1:"explicit,tag:0"`
	Value []byte `asn1:"explicit,tag:1"`
}

type authenticator struct {
	VNO      int           `asn1:"explicit,tag:0"`
	Realm    asn1.RawValue `asn1:"explicit,tag:1"`
	CName    PrincipalName `asn1:"explicit,tag:2"`
	Checksum checksum      `asn1:"explicit,tag:3"`
	CUsec    int           `asn1:"explicit,tag:4"`
	CTime    time.Time     `asn1:"generalized,explicit,tag:5"`
}

type transitedEncoding struct {
	Type     int32  `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

type encTicketPart struct {
	Flags     asn1.BitString    `asn1:"explicit,tag:0"`
	Key       encryptionKey     `asn1:"explicit,tag:1"`
	CRealm    asn1.RawValue     `asn1:"explicit,tag:2"`
	CName     PrincipalName     `asn1:"explicit,tag:3"`
	Transited transitedEncoding `asn1:"explicit,tag:4"`
	AuthTime  time.Time         `asn1:"generalized,explicit,tag:5"`
	StartTime time.Time         `asn1:"generalized,optional,explicit,tag:6"`
	EndTime   time.Time         `asn1:"generalized,explicit,tag:7"`
}

const (
	ErrPrincipalUnknown = 6
	ErrClientRevoked    = 18
	ErrKeyExpired       = 23
	ErrPreauthFailed    = 24
	ErrPreauthRequired  = 25
	ErrSkew             = 37
	ErrResponseTooBig   = 52
)

type Error struct {
	Code int32
	Text string
	data []byte
}

func (e *Error) Error() string {
	name := map[int32]string{
		ErrPrincipalUnknown: "unknown user",
		ErrClientRevoked:    "account disabled or locked",
		ErrKeyExpired:       "password expired",
		ErrPreauthFailed:    "wrong password",
		ErrPreauthRequired:  "pre-authentication required",
		ErrSkew:             "clock too far from the domain",
		ErrResponseTooBig:   "response too big",
	}[e.Code]
	if name == "" {
		name = fmt.Sprintf("error %d", e.Code)
	}
	if e.Text != "" {
		return "krb: " + name + ": " + e.Text
	}
	return "krb: " + name
}

func wrap(tag int, v any) ([]byte, error) {
	return asn1.MarshalWithParams(v, fmt.Sprintf("application,explicit,tag:%d", tag))
}

func application(b []byte) (int, []byte, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(b, &raw); err != nil {
		return 0, nil, err
	}
	if raw.Class != asn1.ClassApplication {
		return 0, nil, fmt.Errorf("krb: unexpected message class %d", raw.Class)
	}
	return raw.Tag, raw.Bytes, nil
}

func parseError(inner []byte) error {
	var e krbError
	if _, err := asn1.Unmarshal(inner, &e); err != nil {
		return err
	}
	return &Error{Code: e.Code, Text: text(e.EText), data: e.EData}
}

func kerberosTime(t time.Time) time.Time {
	return t.UTC().Truncate(time.Second)
}
