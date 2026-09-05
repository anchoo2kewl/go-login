package gologin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const authSecret = "hs-secret"

// legacyToken is an HS256 token in the shape of an app that predates
// go-login: user id in "sub", no "user_id".
func legacyToken(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub, "exp": time.Now().Add(time.Minute).Unix(),
	})
	s, err := tok.SignedString([]byte(authSecret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func legacyResolver(claims jwt.MapClaims) (*User, error) {
	sub, _ := claims["sub"].(string)
	if sub != "legacy-42" {
		return nil, errors.New("unknown legacy subject")
	}
	return &User{ID: 42, Email: "legacy@example.com"}, nil
}

func TestAuthenticatorPrecedence(t *testing.T) {
	f := newFakeClerk(t)
	key := f.addKey("k1")
	store := newFakeStore()
	store.byProvider["clerk:user_123"] = &User{ID: 1, Email: "clerk@example.com"}

	a := NewAuthenticator(AuthenticatorOptions{
		Clerk:      f.verifier(t),
		ClerkStore: store,
		JWTSecret:  authSecret,
		ExtraHS256: legacyResolver,
	})

	native, _ := GenerateToken(2, "native@example.com", authSecret, time.Minute)
	expired, _ := GenerateToken(2, "native@example.com", authSecret, -time.Minute)
	wrongSecret, _ := GenerateToken(2, "native@example.com", "other", time.Minute)

	tests := []struct {
		name   string
		bearer string
		wantID int64
	}{
		{"clerk RS256", f.sign(t, "k1", key, nil), 1},
		{"clerk with Bearer prefix", "Bearer " + f.sign(t, "k1", key, nil), 1},
		{"go-login HS256", native, 2},
		{"go-login HS256 lower-case bearer", "bearer " + native, 2},
		{"legacy HS256 via ExtraHS256", legacyToken(t, "legacy-42"), 42},
		{"legacy HS256 rejected by ExtraHS256", legacyToken(t, "legacy-99"), 0},
		{"expired go-login token", expired, 0},
		{"wrong secret", wrongSecret, 0},
		{"clerk token for unknown user without email", f.sign(t, "k1", key, jwt.MapClaims{"sub": "user_ghost"}), 0},
		{"empty", "", 0},
		{"junk", "junk", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := a.Authenticate(context.Background(), tc.bearer)
			if tc.wantID == 0 {
				if err == nil {
					t.Fatalf("accepted as %+v", u)
				}
				if !errors.Is(err, ErrUnauthenticated) {
					t.Errorf("err %v does not wrap ErrUnauthenticated", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if u.ID != tc.wantID {
				t.Errorf("user = %+v, want id %d", u, tc.wantID)
			}
		})
	}
}

// Without ExtraHS256 a legacy-shaped token is just an invalid token, and
// without Clerk an RS256 token is not even looked at.
func TestAuthenticatorWithoutOptionalParts(t *testing.T) {
	f := newFakeClerk(t)
	key := f.addKey("k1")
	a := NewAuthenticator(AuthenticatorOptions{JWTSecret: authSecret})

	if _, err := a.Authenticate(context.Background(), legacyToken(t, "legacy-42")); err == nil {
		t.Error("legacy token accepted without ExtraHS256")
	}
	if _, err := a.Authenticate(context.Background(), f.sign(t, "k1", key, nil)); err == nil {
		t.Error("RS256 token accepted without Clerk")
	}
	if n := f.fetches.Load(); n != 0 {
		t.Errorf("JWKS fetched %d times with Clerk unconfigured", n)
	}

	// An HS256 token must never be tried against Clerk even when Clerk is on.
	b := NewAuthenticator(AuthenticatorOptions{Clerk: f.verifier(t), ClerkStore: newFakeStore(), JWTSecret: authSecret})
	native, _ := GenerateToken(2, "n@example.com", authSecret, time.Minute)
	if _, err := b.Authenticate(context.Background(), native); err != nil {
		t.Error(err)
	}
	if n := f.fetches.Load(); n != 0 {
		t.Errorf("JWKS fetched %d times for an HS256 token", n)
	}
}

func TestAuthenticatorMiddleware(t *testing.T) {
	a := NewAuthenticator(AuthenticatorOptions{JWTSecret: authSecret})
	native, _ := GenerateToken(5, "m@example.com", authSecret, time.Minute)

	var seen *User
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = UserFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	mw := a.Middleware(next)

	call := func(auth, query string) *httptest.ResponseRecorder {
		seen = nil
		req := httptest.NewRequest(http.MethodGet, "/x"+query, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		return rec
	}

	if rec := call("Bearer "+native, ""); rec.Code != http.StatusNoContent || seen == nil || seen.ID != 5 {
		t.Errorf("header: status %d user %+v", rec.Code, seen)
	}
	if rec := call("", "?token="+native); rec.Code != http.StatusNoContent || seen == nil || seen.ID != 5 {
		t.Errorf("query: status %d user %+v", rec.Code, seen)
	}

	rec := call("", "")
	if rec.Code != http.StatusUnauthorized || seen != nil {
		t.Fatalf("no token: status %d user %+v", rec.Code, seen)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "invalid or expired token" {
		t.Errorf("401 body = %s", rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	if UserFromContext(context.Background()) != nil {
		t.Error("UserFromContext on an empty context is not nil")
	}
}
