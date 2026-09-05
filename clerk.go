// Clerk as an identity provider.
//
// Clerk signs its session tokens with RS256 and publishes the public half at a
// JWKS URL under the instance's Frontend API. Verifying one is therefore a
// local operation once the keys are cached: no round trip to Clerk per
// request, and no shared secret to leak. The keys are fetched lazily so an
// application boots when Clerk is unreachable and only fails the requests
// that actually need it.
//
// Storage follows the same rule as the OAuth side: the verifier hands back an
// identity and lets a store decide what account it belongs to.

package gologin

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ProviderClerk is the provider name Clerk accounts are stored under.
const ProviderClerk = "clerk"

// Sentinel errors for the Clerk verifier.
var (
	// ErrClerkTokenInvalid is returned when a session token does not verify:
	// bad signature, wrong issuer, expired, unknown key, or not RS256.
	ErrClerkTokenInvalid = errors.New("go-login: clerk token is invalid")

	// ErrClerkNoEmail is returned by Resolve when the token maps to no known
	// account and carries no email to find or create one with.
	ErrClerkNoEmail = errors.New("go-login: clerk token has no email address")
)

// jwksRefreshCoolDown is the minimum gap between two JWKS fetches triggered by
// an unknown key id. Without it a stream of garbage tokens with made-up kids
// turns into a stream of requests to Clerk.
const jwksRefreshCoolDown = time.Minute

// ClerkConfig configures a ClerkVerifier.
type ClerkConfig struct {
	// IssuerURL is the instance's Frontend API URL, e.g.
	// "https://clerk.example.com" or "https://xxx.clerk.accounts.dev". It is
	// both the expected "iss" claim and the base for the JWKS URL.
	IssuerURL string

	// HTTPClient is used to fetch the JWKS and user info. Defaults to a client
	// with a ten second timeout.
	HTTPClient *http.Client

	// CacheTTL is how long a fetched JWKS is trusted before being refreshed.
	// Defaults to one hour.
	CacheTTL time.Duration

	// SkipUserInfo stops the verifier calling IssuerURL + "/oauth/userinfo"
	// when a token carries no email claim. Clerk's default session token has
	// no email in it, so the fetch is on unless you have added email to the
	// session token's claims template.
	SkipUserInfo bool
}

// ClerkIdentity is what a verified session token says about its holder.
type ClerkIdentity struct {
	// ClerkID is the Clerk user id (the "sub" claim), e.g. "user_2abc...".
	ClerkID string
	// Email is the primary email if the token or user info carried one.
	Email     string
	Name      string
	FirstName string
	LastName  string
	AvatarURL string
	// Claims is the raw token payload for anything not lifted above.
	Claims map[string]any
}

// ProviderUserInfo converts the identity to the shape UserStore.CreateOAuthUser
// takes, so a Clerk account is created like a Google or GitHub one.
func (id *ClerkIdentity) ProviderUserInfo() ProviderUserInfo {
	return ProviderUserInfo{
		ProviderUserID: id.ClerkID,
		Email:          id.Email,
		Name:           id.Name,
		FirstName:      id.FirstName,
		LastName:       id.LastName,
		AvatarURL:      id.AvatarURL,
	}
}

// ClerkUserStore is the subset of UserStore that Resolve needs. Any existing
// UserStore satisfies it.
type ClerkUserStore interface {
	FindUserByProviderID(ctx context.Context, provider, providerUserID string) (*User, error)
	FindUserByEmail(ctx context.Context, email string) (*User, error)
	LinkOAuthProvider(ctx context.Context, userID int64, provider, providerUserID string) (*User, error)
	CreateOAuthUser(ctx context.Context, info ProviderUserInfo, provider, inviteCode string) (*User, error)
}

// ClerkVerifier verifies Clerk session tokens against the instance's JWKS.
// It is safe for concurrent use.
type ClerkVerifier struct {
	issuer   string
	jwksURL  string
	client   *http.Client
	cacheTTL time.Duration
	userInfo bool

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastRefresh time.Time // last fetch caused by an unknown kid
}

// NewClerkVerifier builds a verifier. It does not contact Clerk; the JWKS is
// fetched on the first token that needs it.
func NewClerkVerifier(cfg ClerkConfig) (*ClerkVerifier, error) {
	issuer := strings.TrimRight(strings.TrimSpace(cfg.IssuerURL), "/")
	if issuer == "" {
		return nil, fmt.Errorf("go-login: ClerkConfig.IssuerURL is required")
	}
	if !strings.HasPrefix(issuer, "https://") && !strings.HasPrefix(issuer, "http://") {
		return nil, fmt.Errorf("go-login: ClerkConfig.IssuerURL must be an absolute URL")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &ClerkVerifier{
		issuer:   issuer,
		jwksURL:  issuer + "/.well-known/jwks.json",
		client:   client,
		cacheTTL: ttl,
		userInfo: !cfg.SkipUserInfo,
	}, nil
}

// Issuer returns the issuer URL the verifier expects.
func (v *ClerkVerifier) Issuer() string { return v.issuer }

// Verify checks the token's signature, issuer and validity window, and
// returns what it says about the holder. Errors wrap ErrClerkTokenInvalid.
func (v *ClerkVerifier) Verify(ctx context.Context, token string) (*ClerkIdentity, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("%w: empty token", ErrClerkTokenInvalid)
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		return v.keyfunc(ctx, t)
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClerkTokenInvalid, err)
	}
	if !parsed.Valid {
		return nil, ErrClerkTokenInvalid
	}

	id := identityFromClaims(claims)
	if id.ClerkID == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrClerkTokenInvalid)
	}

	if id.Email == "" && v.userInfo {
		// Best effort: a user info failure is not a verification failure.
		// The token is good; we just know less about who holds it.
		_ = v.fetchUserInfo(ctx, token, id)
	}
	return id, nil
}

// Keyfunc is a jwt.Keyfunc for applications that want to parse Clerk tokens
// themselves. It only ever returns RSA public keys, and only for RS256.
func (v *ClerkVerifier) Keyfunc(t *jwt.Token) (any, error) {
	return v.keyfunc(context.Background(), t)
}

// Resolve verifies the token and maps it to an account through the store:
// found by Clerk id, else linked to the account with the same email, else
// created. The same decision tree as the OAuth callback, minus invite gating.
func (v *ClerkVerifier) Resolve(ctx context.Context, token string, store ClerkUserStore) (*User, *ClerkIdentity, error) {
	if store == nil {
		return nil, nil, fmt.Errorf("go-login: ClerkUserStore must not be nil")
	}
	id, err := v.Verify(ctx, token)
	if err != nil {
		return nil, nil, err
	}

	u, err := store.FindUserByProviderID(ctx, ProviderClerk, id.ClerkID)
	if err != nil {
		return nil, id, fmt.Errorf("go-login: FindUserByProviderID: %w", err)
	}
	if u != nil {
		return u, id, nil
	}

	if id.Email == "" {
		return nil, id, ErrClerkNoEmail
	}

	u, err = store.FindUserByEmail(ctx, id.Email)
	if err != nil {
		return nil, id, fmt.Errorf("go-login: FindUserByEmail: %w", err)
	}
	if u != nil {
		linked, err := store.LinkOAuthProvider(ctx, u.ID, ProviderClerk, id.ClerkID)
		if err != nil {
			return nil, id, fmt.Errorf("go-login: LinkOAuthProvider: %w", err)
		}
		return linked, id, nil
	}

	created, err := store.CreateOAuthUser(ctx, id.ProviderUserInfo(), ProviderClerk, "")
	if err != nil {
		return nil, id, fmt.Errorf("go-login: CreateOAuthUser: %w", err)
	}
	return created, id, nil
}

// ----- claims ----------------------------------------------------------------

func identityFromClaims(claims jwt.MapClaims) *ClerkIdentity {
	id := &ClerkIdentity{Claims: map[string]any(claims)}
	id.ClerkID = claimString(claims, "sub")

	id.Email = claimString(claims, "email")
	if id.Email == "" {
		if list, ok := claims["emails"].([]any); ok && len(list) > 0 {
			id.Email, _ = list[0].(string)
		}
	}
	if id.Email == "" {
		id.Email = claimString(claims, "primary_email")
	}
	if id.Email == "" {
		id.Email = claimString(claims, "email_address")
	}

	id.FirstName = claimString(claims, "first_name")
	if id.FirstName == "" {
		id.FirstName = claimString(claims, "given_name")
	}
	id.LastName = claimString(claims, "last_name")
	if id.LastName == "" {
		id.LastName = claimString(claims, "family_name")
	}
	id.Name = strings.TrimSpace(id.FirstName + " " + id.LastName)
	if id.Name == "" {
		id.Name = claimString(claims, "name")
	}
	id.AvatarURL = claimString(claims, "image_url")
	if id.AvatarURL == "" {
		id.AvatarURL = claimString(claims, "picture")
	}
	return id
}

func claimString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return strings.TrimSpace(s)
}

// fetchUserInfo fills in email and name from the Frontend API's user info
// endpoint, which accepts the session token as a bearer credential.
func (v *ClerkVerifier) fetchUserInfo(ctx context.Context, token string, id *ClerkIdentity) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.issuer+"/oauth/userinfo", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("go-login: clerk userinfo returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var info map[string]any
	if err := json.Unmarshal(body, &info); err != nil {
		return err
	}

	if e := claimString(info, "email"); e != "" {
		id.Email = e
	} else if e := claimString(info, "email_address"); e != "" {
		id.Email = e
	}
	if id.FirstName == "" {
		id.FirstName = claimString(info, "given_name")
	}
	if id.LastName == "" {
		id.LastName = claimString(info, "family_name")
	}
	if id.Name == "" {
		id.Name = claimString(info, "name")
	}
	if id.Name == "" {
		id.Name = strings.TrimSpace(id.FirstName + " " + id.LastName)
	}
	if id.AvatarURL == "" {
		id.AvatarURL = claimString(info, "picture")
	}
	return nil
}

// ----- JWKS ------------------------------------------------------------------

func (v *ClerkVerifier) keyfunc(ctx context.Context, t *jwt.Token) (any, error) {
	if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok || t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
		return nil, fmt.Errorf("go-login: unexpected signing method %v", t.Header["alg"])
	}
	kid, _ := t.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("go-login: token has no kid")
	}
	return v.keyFor(ctx, kid)
}

// keyFor returns the key for kid, fetching the JWKS when the cache is cold or
// stale, and once more — rate limited — when the kid is simply unknown, which
// is what a key rotation looks like from here.
func (v *ClerkVerifier) keyFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	if v.keys == nil || now.Sub(v.fetchedAt) > v.cacheTTL {
		if err := v.refreshLocked(ctx); err != nil {
			return nil, err
		}
	}
	if key, ok := v.keys[kid]; ok {
		return key, nil
	}

	if now.Sub(v.lastRefresh) < jwksRefreshCoolDown {
		return nil, fmt.Errorf("go-login: unknown key id %q", kid)
	}
	v.lastRefresh = now
	if err := v.refreshLocked(ctx); err != nil {
		return nil, err
	}
	if key, ok := v.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("go-login: unknown key id %q", kid)
}

// refreshLocked fetches the JWKS. Caller holds v.mu.
func (v *ClerkVerifier) refreshLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("go-login: fetching clerk JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("go-login: clerk JWKS returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("go-login: reading clerk JWKS: %w", err)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return err
	}
	v.keys = keys
	v.fetchedAt = time.Now()
	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// parseJWKS reads the RSA keys out of a JWK Set. Keys of other types are
// skipped rather than rejected, so an EC key appearing alongside does not take
// verification down.
func parseJWKS(body []byte) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("go-login: clerk JWKS is not JSON: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := jwkToRSA(k)
		if err != nil {
			return nil, fmt.Errorf("go-login: clerk JWKS key %q: %w", k.Kid, err)
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("go-login: clerk JWKS has no RSA signing keys")
	}
	return keys, nil
}

func jwkToRSA(k jwk) (*rsa.PublicKey, error) {
	n, err := decodeB64URL(k.N)
	if err != nil {
		return nil, fmt.Errorf("modulus: %w", err)
	}
	e, err := decodeB64URL(k.E)
	if err != nil {
		return nil, fmt.Errorf("exponent: %w", err)
	}
	if len(n) == 0 || len(e) == 0 {
		return nil, errors.New("empty modulus or exponent")
	}
	exp := new(big.Int).SetBytes(e)
	if !exp.IsInt64() || exp.Int64() < 3 || exp.Int64() > int64(^uint32(0)) {
		return nil, errors.New("exponent out of range")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}, nil
}

// decodeB64URL accepts base64url with or without padding, since both turn up
// in the wild.
func decodeB64URL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
