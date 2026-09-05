package gologin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeClerk is a stand-in for a Clerk Frontend API: a JWKS endpoint that
// counts fetches, and a userinfo endpoint that answers for one token.
type fakeClerk struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	keys    map[string]*rsa.PrivateKey // kid -> key currently published
	fetches atomic.Int32
	// userinfo maps a session token to the JSON body /oauth/userinfo returns.
	userinfo map[string]map[string]any
}

func newFakeClerk(t *testing.T) *fakeClerk {
	t.Helper()
	f := &fakeClerk{t: t, keys: map[string]*rsa.PrivateKey{}, userinfo: map[string]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		f.fetches.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		var set struct {
			Keys []map[string]string `json:"keys"`
		}
		for kid, k := range f.keys {
			set.Keys = append(set.Keys, map[string]string{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
				"n": base64.RawURLEncoding.EncodeToString(k.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.PublicKey.E)).Bytes()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	mux.HandleFunc("/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		body, ok := f.userinfo[bearerToken(r.Header.Get("Authorization"))]
		f.mu.Unlock()
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeClerk) issuer() string { return f.srv.URL }

func (f *fakeClerk) addKey(kid string) *rsa.PrivateKey {
	f.t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	f.keys[kid] = k
	f.mu.Unlock()
	return k
}

func (f *fakeClerk) verifier(t *testing.T) *ClerkVerifier {
	t.Helper()
	v, err := NewClerkVerifier(ClerkConfig{IssuerURL: f.issuer()})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// sign mints an RS256 token with the given kid and claims merged over sane
// defaults (sub, iss, exp).
func (f *fakeClerk) sign(t *testing.T, kid string, key *rsa.PrivateKey, extra jwt.MapClaims) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user_123",
		"iss": f.issuer(),
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	}
	for k, val := range extra {
		claims[k] = val
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewClerkVerifierIsLazyAndValidates(t *testing.T) {
	if _, err := NewClerkVerifier(ClerkConfig{}); err == nil {
		t.Error("an empty issuer was accepted")
	}
	if _, err := NewClerkVerifier(ClerkConfig{IssuerURL: "clerk.example.com"}); err == nil {
		t.Error("a bare host was accepted")
	}
	f := newFakeClerk(t)
	v, err := NewClerkVerifier(ClerkConfig{IssuerURL: f.issuer() + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Issuer(); got != f.issuer() {
		t.Errorf("issuer %q, want %q", got, f.issuer())
	}
	if n := f.fetches.Load(); n != 0 {
		t.Errorf("construction fetched the JWKS %d times; want lazy", n)
	}
}

func TestClerkVerify(t *testing.T) {
	f := newFakeClerk(t)
	key := f.addKey("k1")
	other, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name    string
		token   func() string
		wantErr bool
		check   func(t *testing.T, id *ClerkIdentity)
	}{
		{
			name: "valid token with email claims",
			token: func() string {
				return f.sign(t, "k1", key, jwt.MapClaims{
					"email": "a@example.com", "first_name": "Ada", "last_name": "Lovelace",
					"image_url": "https://img/ada.png",
				})
			},
			check: func(t *testing.T, id *ClerkIdentity) {
				if id.ClerkID != "user_123" || id.Email != "a@example.com" || id.Name != "Ada Lovelace" ||
					id.FirstName != "Ada" || id.LastName != "Lovelace" || id.AvatarURL != "https://img/ada.png" {
					t.Errorf("identity = %+v", id)
				}
				if id.Claims["sub"] != "user_123" {
					t.Error("raw claims not carried")
				}
			},
		},
		{
			name: "emails array and name fallback",
			token: func() string {
				return f.sign(t, "k1", key, jwt.MapClaims{"emails": []string{"b@example.com"}, "name": "B"})
			},
			check: func(t *testing.T, id *ClerkIdentity) {
				if id.Email != "b@example.com" || id.Name != "B" {
					t.Errorf("identity = %+v", id)
				}
			},
		},
		{
			name:  "primary_email",
			token: func() string { return f.sign(t, "k1", key, jwt.MapClaims{"primary_email": "c@example.com"}) },
			check: func(t *testing.T, id *ClerkIdentity) {
				if id.Email != "c@example.com" {
					t.Errorf("email = %q", id.Email)
				}
			},
		},
		{
			name:    "wrong issuer",
			token:   func() string { return f.sign(t, "k1", key, jwt.MapClaims{"iss": "https://someone-else.example"}) },
			wantErr: true,
		},
		{
			name:    "expired",
			token:   func() string { return f.sign(t, "k1", key, jwt.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()}) },
			wantErr: true,
		},
		{
			name:    "wrong key",
			token:   func() string { return f.sign(t, "k1", other, nil) },
			wantErr: true,
		},
		{
			name:    "no sub",
			token:   func() string { return f.sign(t, "k1", key, jwt.MapClaims{"sub": ""}) },
			wantErr: true,
		},
		{
			name:    "garbage",
			token:   func() string { return "not.a.jwt" },
			wantErr: true,
		},
	}

	v := f.verifier(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, err := v.Verify(context.Background(), tc.token())
			if tc.wantErr {
				if err == nil {
					t.Fatal("token accepted")
				}
				if !errors.Is(err, ErrClerkTokenInvalid) {
					t.Errorf("error %v does not wrap ErrClerkTokenInvalid", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, id)
		})
	}
	if n := f.fetches.Load(); n != 1 {
		t.Errorf("JWKS fetched %d times across the table; want 1 (cached)", n)
	}
}

// An unknown kid is what a key rotation looks like: refresh once, then hold
// off so a stream of bad tokens does not become a stream of requests.
func TestClerkUnknownKidRefreshesOnceThenCoolsDown(t *testing.T) {
	f := newFakeClerk(t)
	k1 := f.addKey("k1")
	v := f.verifier(t)

	if _, err := v.Verify(context.Background(), f.sign(t, "k1", k1, nil)); err != nil {
		t.Fatal(err)
	}
	if n := f.fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}

	// Rotate: publish k2, sign with it.
	k2 := f.addKey("k2")
	if _, err := v.Verify(context.Background(), f.sign(t, "k2", k2, nil)); err != nil {
		t.Fatalf("token under rotated key rejected: %v", err)
	}
	if n := f.fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (one refresh for the new kid)", n)
	}

	// A made-up kid inside the cool-down must not fetch again.
	k3, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := v.Verify(context.Background(), f.sign(t, "k3", k3, nil)); err == nil {
		t.Fatal("token with unpublished kid accepted")
	}
	if n := f.fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (cool-down should suppress the refresh)", n)
	}

	// Once the cool-down has passed a refresh is allowed again.
	v.mu.Lock()
	v.lastRefresh = time.Now().Add(-2 * jwksRefreshCoolDown)
	v.mu.Unlock()
	if _, err := v.Verify(context.Background(), f.sign(t, "k3", k3, nil)); err == nil {
		t.Fatal("token with unpublished kid accepted")
	}
	if n := f.fetches.Load(); n != 3 {
		t.Fatalf("fetches = %d, want 3", n)
	}
}

// The classic key-confusion attack: sign with HS256 using the public key
// bytes as the HMAC secret. RS256-only means it never gets a hearing.
func TestClerkRejectsHS256SignedWithPublicKey(t *testing.T) {
	f := newFakeClerk(t)
	key := f.addKey("k1")
	v := f.verifier(t)

	claims := jwt.MapClaims{"sub": "user_123", "iss": f.issuer(), "exp": time.Now().Add(time.Minute).Unix()}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = "k1"
	forged, err := tok.SignedString(key.PublicKey.N.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), forged); err == nil {
		t.Fatal("HS256 token accepted")
	}
	if _, err := v.Keyfunc(tok); err == nil {
		t.Fatal("Keyfunc handed out a key for HS256")
	}
}

func TestClerkKeyfuncReturnsRSAPublicKey(t *testing.T) {
	f := newFakeClerk(t)
	key := f.addKey("k1")
	v := f.verifier(t)

	token := f.sign(t, "k1", key, nil)
	parsed, err := jwt.Parse(token, v.Keyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("raw parse failed: %v", err)
	}
}

func TestClerkFetchesUserInfoWhenTokenHasNoEmail(t *testing.T) {
	f := newFakeClerk(t)
	key := f.addKey("k1")
	token := f.sign(t, "k1", key, nil)
	f.userinfo[token] = map[string]any{
		"email_address": "info@example.com", "given_name": "Grace", "family_name": "Hopper", "picture": "https://img/g.png",
	}

	v := f.verifier(t)
	id, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if id.Email != "info@example.com" || id.Name != "Grace Hopper" || id.AvatarURL != "https://img/g.png" {
		t.Errorf("identity = %+v", id)
	}

	// Switched off, the token still verifies but says less.
	off, _ := NewClerkVerifier(ClerkConfig{IssuerURL: f.issuer(), SkipUserInfo: true})
	id, err = off.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if id.Email != "" {
		t.Errorf("email %q fetched with SkipUserInfo", id.Email)
	}

	// A failing userinfo endpoint is not a verification failure.
	unknown := f.sign(t, "k1", key, jwt.MapClaims{"sub": "user_nobody"})
	if _, err := v.Verify(context.Background(), unknown); err != nil {
		t.Errorf("userinfo 401 turned into a verify error: %v", err)
	}
}

// ----- Resolve ----------------------------------------------------------------

// fakeStore records what Resolve asked of it. It satisfies the full UserStore
// so the handler tests can use it too.
type fakeStore struct {
	byProvider map[string]*User // provider+":"+id
	byEmail    map[string]*User
	nextID     int64
	linked     []string
	created    []ProviderUserInfo
	err        error
}

func newFakeStore() *fakeStore {
	return &fakeStore{byProvider: map[string]*User{}, byEmail: map[string]*User{}, nextID: 100}
}

func (s *fakeStore) FindUserByProviderID(_ context.Context, provider, id string) (*User, error) {
	return s.byProvider[provider+":"+id], s.err
}
func (s *fakeStore) FindUserByEmail(_ context.Context, email string) (*User, error) {
	return s.byEmail[email], s.err
}
func (s *fakeStore) GetUserAuthProvider(context.Context, int64) (string, error) { return "clerk", nil }
func (s *fakeStore) ValidateInviteCode(context.Context, string) (*InviteInfo, error) {
	return nil, nil
}
func (s *fakeStore) LinkOAuthProvider(_ context.Context, userID int64, provider, id string) (*User, error) {
	s.linked = append(s.linked, provider+":"+id)
	for _, u := range s.byEmail {
		if u.ID == userID {
			s.byProvider[provider+":"+id] = u
			return u, nil
		}
	}
	return nil, errors.New("no such user")
}
func (s *fakeStore) CreateOAuthUser(_ context.Context, info ProviderUserInfo, provider, invite string) (*User, error) {
	s.created = append(s.created, info)
	s.nextID++
	u := &User{ID: s.nextID, Email: info.Email}
	s.byProvider[provider+":"+info.ProviderUserID] = u
	s.byEmail[info.Email] = u
	return u, nil
}

func TestClerkResolveDecisionTree(t *testing.T) {
	f := newFakeClerk(t)
	key := f.addKey("k1")
	v := f.verifier(t)
	ctx := context.Background()

	t.Run("found by provider id", func(t *testing.T) {
		s := newFakeStore()
		s.byProvider["clerk:user_123"] = &User{ID: 7, Email: "old@example.com"}
		u, id, err := v.Resolve(ctx, f.sign(t, "k1", key, jwt.MapClaims{"email": "new@example.com"}), s)
		if err != nil {
			t.Fatal(err)
		}
		if u.ID != 7 || id.ClerkID != "user_123" {
			t.Errorf("user %+v identity %+v", u, id)
		}
		if len(s.linked)+len(s.created) != 0 {
			t.Error("store was written to on the happy path")
		}
	})

	t.Run("linked by email", func(t *testing.T) {
		s := newFakeStore()
		s.byEmail["a@example.com"] = &User{ID: 9, Email: "a@example.com"}
		u, _, err := v.Resolve(ctx, f.sign(t, "k1", key, jwt.MapClaims{"email": "a@example.com"}), s)
		if err != nil {
			t.Fatal(err)
		}
		if u.ID != 9 {
			t.Errorf("user = %+v", u)
		}
		if len(s.linked) != 1 || s.linked[0] != "clerk:user_123" {
			t.Errorf("linked = %v", s.linked)
		}
		if len(s.created) != 0 {
			t.Error("a user was created instead of linked")
		}
	})

	t.Run("created", func(t *testing.T) {
		s := newFakeStore()
		u, _, err := v.Resolve(ctx, f.sign(t, "k1", key, jwt.MapClaims{"email": "n@example.com", "first_name": "N"}), s)
		if err != nil {
			t.Fatal(err)
		}
		if u.Email != "n@example.com" || u.ID == 0 {
			t.Errorf("user = %+v", u)
		}
		if len(s.created) != 1 || s.created[0].ProviderUserID != "user_123" || s.created[0].Name != "N" {
			t.Errorf("created = %+v", s.created)
		}
	})

	t.Run("no email and unknown", func(t *testing.T) {
		s := newFakeStore()
		_, _, err := v.Resolve(ctx, f.sign(t, "k1", key, jwt.MapClaims{"sub": "user_nobody"}), s)
		if !errors.Is(err, ErrClerkNoEmail) {
			t.Errorf("err = %v, want ErrClerkNoEmail", err)
		}
		if len(s.created) != 0 {
			t.Error("a user was created without an email")
		}
	})

	t.Run("no email but known", func(t *testing.T) {
		s := newFakeStore()
		s.byProvider["clerk:user_nobody"] = &User{ID: 3, Email: "x@example.com"}
		u, _, err := v.Resolve(ctx, f.sign(t, "k1", key, jwt.MapClaims{"sub": "user_nobody"}), s)
		if err != nil || u.ID != 3 {
			t.Errorf("user %+v err %v", u, err)
		}
	})

	t.Run("store error", func(t *testing.T) {
		s := newFakeStore()
		s.err = errors.New("db down")
		_, _, err := v.Resolve(ctx, f.sign(t, "k1", key, nil), s)
		if err == nil || !strings.Contains(err.Error(), "db down") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("bad token never reaches the store", func(t *testing.T) {
		s := newFakeStore()
		s.err = errors.New("should not be called")
		_, _, err := v.Resolve(ctx, "junk", s)
		if !errors.Is(err, ErrClerkTokenInvalid) {
			t.Errorf("err = %v", err)
		}
	})
}

// ----- Handler exchange -------------------------------------------------------

func TestConfigValidateAcceptsClerkOnly(t *testing.T) {
	cfg := &Config{JWTSecret: "s"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "Google, GitHub or Clerk") {
		t.Errorf("no-provider error = %v", err)
	}
	cfg.Clerk = &ClerkConfig{}
	if err := cfg.Validate(); err == nil {
		t.Error("Clerk without IssuerURL accepted")
	}
	cfg.Clerk.IssuerURL = "https://clerk.example.com"
	if err := cfg.Validate(); err != nil {
		t.Errorf("Clerk-only config refused: %v", err)
	}
	// OAuth still needs the redirect plumbing.
	oauth := &Config{JWTSecret: "s", Google: &OAuthProviderConfig{ClientID: "a", ClientSecret: "b", RedirectURL: "c"}}
	if err := oauth.Validate(); err == nil {
		t.Error("OAuth config without SuccessURL accepted")
	}
}

func TestHandleClerkExchange(t *testing.T) {
	f := newFakeClerk(t)
	key := f.addKey("k1")
	store := newFakeStore()
	var loggedIn int64
	h, err := NewHandler(&Config{
		Clerk:          &ClerkConfig{IssuerURL: f.issuer()},
		JWTSecret:      "hs-secret",
		OnLoginSuccess: func(_ *http.Request, id int64) { loggedIn = id },
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	if h.Clerk() == nil {
		t.Fatal("Clerk() is nil")
	}

	good := f.sign(t, "k1", key, jwt.MapClaims{"email": "e@example.com"})

	post := func(body string, auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/clerk/exchange", strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.HandleClerkExchange(rec, req)
		return rec
	}

	rec := post(`{"token":"`+good+`"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		Token string `json:"token"`
		User  struct {
			ID    int64  `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.User.Email != "e@example.com" || out.User.ID == 0 || loggedIn != out.User.ID {
		t.Errorf("response %+v, OnLoginSuccess saw %d", out, loggedIn)
	}
	claims, err := ValidateToken(out.Token, "hs-secret")
	if err != nil || claims.UserID != out.User.ID {
		t.Errorf("issued token does not validate: %v", err)
	}

	// Bearer header works too, and the same account comes back.
	rec = post("", "Bearer "+good)
	if rec.Code != http.StatusOK {
		t.Errorf("bearer: status %d", rec.Code)
	}
	if len(store.created) != 1 {
		t.Errorf("created %d users across two exchanges", len(store.created))
	}

	rec = post(`{"token":"junk"}`, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token: status %d", rec.Code)
	}
	rec = post(`{}`, "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing token: status %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	get := httptest.NewRecorder()
	h.HandleClerkExchange(get, req)
	if get.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status %d", get.Code)
	}
}
