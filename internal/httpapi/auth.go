package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

type Principal struct {
	OwnerID     string
	Read, Write bool
}
type Authenticator interface {
	Authenticate(context.Context, string) (Principal, error)
}
type credential struct {
	hash      [32]byte
	principal Principal
}

// StaticAuth stores token hashes and returns stable server-controlled owner IDs.
type StaticAuth struct{ credentials []credential }

func NewStaticAuth(tokens map[string]Principal) (*StaticAuth, error) {
	if len(tokens) == 0 {
		return nil, fmt.Errorf("at least one API token is required")
	}
	a := &StaticAuth{}
	for token, p := range tokens {
		if len(token) < 32 || p.OwnerID == "" {
			return nil, fmt.Errorf("token must be at least 32 bytes and owner must be set")
		}
		a.credentials = append(a.credentials, credential{sha256.Sum256([]byte(token)), p})
	}
	return a, nil
}
func (a *StaticAuth) Authenticate(ctx context.Context, token string) (Principal, error) {
	if err := ctx.Err(); err != nil {
		return Principal{}, err
	}
	h := sha256.Sum256([]byte(token))
	var p Principal
	found := false
	for _, c := range a.credentials {
		if subtle.ConstantTimeCompare(h[:], c.hash[:]) == 1 {
			p = c.principal
			found = true
		}
	}
	if !found {
		return Principal{}, fmt.Errorf("invalid credential")
	}
	return p, nil
}
