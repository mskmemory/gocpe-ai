package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

type cursor struct {
	Scope   string `json:"s"`
	After   string `json:"a"`
	Expires int64  `json:"e"`
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func hashValue(v any) string { b, _ := json.Marshal(v); return digest(b) }
func (s *Service) sign(scope, after string, until time.Time) string {
	b, _ := json.Marshal(cursor{scope, after, until.Unix()})
	m := hmac.New(sha256.New, s.key)
	m.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func (s *Service) readCursor(token, scope string) (string, error) {
	if token == "" {
		return "", nil
	}
	bad := &Fault{Status: 400, Code: "INVALID_CURSOR", Message: "Cursor is invalid or expired"}
	if len(token) > 4096 {
		return "", bad
	}
	p := strings.Split(token, ".")
	if len(p) != 2 {
		return "", bad
	}
	b, e := base64.RawURLEncoding.DecodeString(p[0])
	if e != nil {
		return "", bad
	}
	sig, e := base64.RawURLEncoding.DecodeString(p[1])
	if e != nil {
		return "", bad
	}
	m := hmac.New(sha256.New, s.key)
	m.Write(b)
	if !hmac.Equal(sig, m.Sum(nil)) {
		return "", bad
	}
	var c cursor
	if json.Unmarshal(b, &c) != nil || c.Scope != scope || c.Expires <= s.now().Unix() {
		return "", bad
	}
	return c.After, nil
}
func pageLimit(n int) (int, error) {
	if n == 0 {
		return 100, nil
	}
	if n < 1 || n > 200 {
		return 0, &Fault{Status: 400, Code: "INVALID_QUERY", Message: "limit must be between 1 and 200"}
	}
	return n, nil
}
