// Request authentication that accepts more than one kind of token.
//
// An app moving to Clerk still has sessions issued under its own HS256
// secret, and may have an older claim shape from before go-login. The
// Authenticator tries each in turn, cheapest check first, and the handlers
// behind it see one *User whichever way it came in.

package gologin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ErrUnauthenticated is returned by Authenticate when no configured method
// accepts the token.
var ErrUnauthenticated = errors.New("go-login: invalid or expired token")

// contextKey is unexported so nothing outside this package can collide with it.
type contextKey string

// ContextKeyUser is where Middleware stores the authenticated *User. Read it
// with UserFromContext.
const ContextKeyUser = contextKey("gologin.user")

// AuthenticatorOptions configures an Authenticator. Everything is optional,
// though an Authenticator with nothing set accepts nothing.
type AuthenticatorOptions struct {
	// Clerk verifies RS256 session tokens. Requires ClerkStore to turn an
	// identity into a *User.
	Clerk *ClerkVerifier
	// ClerkStore maps a Clerk identity to an account, as in
	// ClerkVerifier.Resolve.
	ClerkStore ClerkUserStore

	// JWTSecret verifies the HS256 tokens go-login itself issues.
	JWTSecret string

	// ExtraHS256 handles HS256 tokens signed with JWTSecret whose claims are
	// not go-login's Claims — an older app that put the user id in "sub", say.
	// It runs only when the standard Claims shape did not yield a user id.
	// Return (nil, err) to reject.
	ExtraHS256 func(claims jwt.MapClaims) (*User, error)
}

// Authenticator turns a bearer token into a *User.
type Authenticator struct {
	opts AuthenticatorOptions
}

// NewAuthenticator builds an Authenticator.
func NewAuthenticator(opts AuthenticatorOptions) *Authenticator {
	return &Authenticator{opts: opts}
}

// Authenticate accepts a raw token or an "Authorization" header value with a
// "Bearer " prefix. Clerk tokens are tried first when the token is RS256,
// then go-login's own HS256 claims, then ExtraHS256. Errors wrap
// ErrUnauthenticated.
func (a *Authenticator) Authenticate(ctx context.Context, bearer string) (*User, error) {
	token := strings.TrimSpace(bearer)
	if len(token) > 7 && strings.EqualFold(token[:7], "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	if token == "" {
		return nil, fmt.Errorf("%w: no token", ErrUnauthenticated)
	}

	alg := tokenAlg(token)
	var errs []error

	if a.opts.Clerk != nil && alg == jwt.SigningMethodRS256.Alg() {
		if a.opts.ClerkStore == nil {
			return nil, fmt.Errorf("%w: clerk configured without a store", ErrUnauthenticated)
		}
		u, _, err := a.opts.Clerk.Resolve(ctx, token, a.opts.ClerkStore)
		if err == nil && u != nil {
			return u, nil
		}
		errs = append(errs, err)
	}

	if a.opts.JWTSecret != "" && alg != jwt.SigningMethodRS256.Alg() {
		if c, err := ValidateToken(token, a.opts.JWTSecret); err == nil && c.UserID != 0 {
			return &User{ID: c.UserID, Email: c.Email}, nil
		} else if err != nil {
			errs = append(errs, err)
		}

		if a.opts.ExtraHS256 != nil {
			claims := jwt.MapClaims{}
			_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
				return []byte(a.opts.JWTSecret), nil
			}, jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}))
			if err == nil {
				u, err := a.opts.ExtraHS256(claims)
				if err == nil && u != nil {
					return u, nil
				}
				errs = append(errs, err)
			} else {
				errs = append(errs, err)
			}
		}
	}

	return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, errors.Join(errs...))
}

// Middleware authenticates from "Authorization: Bearer" or, failing that, a
// "?token=" query parameter, and stores the *User for UserFromContext. It
// answers 401 with a JSON body when neither yields a user.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		if bearer == "" {
			bearer = r.URL.Query().Get("token")
		}
		u, err := a.Authenticate(r.Context(), bearer)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer realm="go-login"`)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid or expired token"})
			return
		}
		next.ServeHTTP(w, r.WithContext(ContextWithUser(r.Context(), u)))
	})
}

// ContextWithUser returns ctx carrying u for UserFromContext.
func ContextWithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, ContextKeyUser, u)
}

// UserFromContext returns the user stored by Middleware, or nil.
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(ContextKeyUser).(*User)
	return u
}

// tokenAlg reads the "alg" from a JWT header without verifying anything.
// It only decides which verifier to try; every verifier checks alg itself.
func tokenAlg(token string) string {
	head, _, ok := strings.Cut(token, ".")
	if !ok {
		return ""
	}
	raw, err := decodeB64URL(head)
	if err != nil {
		return ""
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return ""
	}
	return h.Alg
}
