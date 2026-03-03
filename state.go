package gologin

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// stateClaims is the payload of the OAuth state JWT used for CSRF protection.
// It is signed with StateSecret (not JWTSecret) and expires in 10 minutes.
type stateClaims struct {
	Provider   string `json:"provider"`
	InviteCode string `json:"invite_code,omitempty"`
	Nonce      string `json:"nonce"`
	jwt.RegisteredClaims
}

// signState creates a signed HS256 JWT to use as the OAuth "state" parameter.
// The JWT encodes the provider name, an optional invite code, and a random
// nonce. Expiry is 10 minutes.
func signState(provider, inviteCode, secret string) (string, error) {
	nonce, err := randomHex(16)
	if err != nil {
		return "", fmt.Errorf("go-login: failed to generate state nonce: %w", err)
	}

	now := time.Now()
	claims := stateClaims{
		Provider:   provider,
		InviteCode: inviteCode,
		Nonce:      nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("go-login: failed to sign state JWT: %w", err)
	}
	return signed, nil
}

// parseState verifies the state JWT and returns the embedded provider and
// invite code. Returns ErrStateInvalid when verification fails or the token
// has expired.
func parseState(stateToken, secret string) (provider, inviteCode string, err error) {
	token, err := jwt.ParseWithClaims(stateToken, &stateClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return "", "", ErrStateInvalid
	}

	claims, ok := token.Claims.(*stateClaims)
	if !ok {
		return "", "", ErrStateInvalid
	}
	return claims.Provider, claims.InviteCode, nil
}

// randomHex returns n random bytes encoded as a lower-case hex string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
