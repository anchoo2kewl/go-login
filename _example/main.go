// Package main shows a minimal example of wiring go-login into a net/http
// application. Real applications will use a proper router and a real database.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	gologin "github.com/anchoo2kewl/go-login"
)

// memStore is a toy in-memory UserStore for demonstration.
type memStore struct {
	users    map[int64]*gologin.User
	byEmail  map[string]*gologin.User
	byProv   map[string]*gologin.User // "provider:providerUserID" -> user
	nextID   int64
	invites  map[string]*gologin.InviteInfo
}

func newMemStore() *memStore {
	return &memStore{
		users:   make(map[int64]*gologin.User),
		byEmail: make(map[string]*gologin.User),
		byProv:  make(map[string]*gologin.User),
		invites: map[string]*gologin.InviteInfo{
			"DEMO-INVITE": {Code: "DEMO-INVITE"},
		},
		nextID: 1,
	}
}

func (s *memStore) FindUserByProviderID(_ context.Context, provider, id string) (*gologin.User, error) {
	key := provider + ":" + id
	u, ok := s.byProv[key]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (s *memStore) FindUserByEmail(_ context.Context, email string) (*gologin.User, error) {
	u, ok := s.byEmail[email]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (s *memStore) GetUserAuthProvider(_ context.Context, userID int64) (string, error) {
	// In a real app this would query the oauth_providers table.
	return "password", nil
}

func (s *memStore) CreateOAuthUser(_ context.Context, info gologin.ProviderUserInfo, provider, _ string) (*gologin.User, error) {
	u := &gologin.User{ID: s.nextID, Email: info.Email}
	s.nextID++
	s.users[u.ID] = u
	s.byEmail[u.Email] = u
	s.byProv[provider+":"+info.ProviderUserID] = u
	return u, nil
}

func (s *memStore) ValidateInviteCode(_ context.Context, code string) (*gologin.InviteInfo, error) {
	inv, ok := s.invites[code]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

func main() {
	store := newMemStore()

	loginHandler, err := gologin.NewHandler(&gologin.Config{
		Google: &gologin.OAuthProviderConfig{
			ClientID:     "YOUR_GOOGLE_CLIENT_ID",
			ClientSecret: "YOUR_GOOGLE_CLIENT_SECRET",
			RedirectURL:  "http://localhost:8080/auth/google/callback",
		},
		SuccessURL:  "http://localhost:8080/welcome",
		ErrorURL:    "http://localhost:8080/login",
		StateSecret: "state-secret-32-bytes-random!!",
		JWTSecret:   "jwt-secret-32-bytes-random-here!",
	}, store)
	if err != nil {
		log.Fatalf("go-login init: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/google", loginHandler.HandleGoogleInitiate)
	mux.HandleFunc("GET /auth/google/callback", loginHandler.HandleGoogleCallback)
	mux.HandleFunc("GET /auth/github/login", loginHandler.HandleGithubInitiate)
	mux.HandleFunc("GET /auth/github/login/callback", loginHandler.HandleGithubCallback)

	mux.HandleFunc("GET /welcome", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		fmt.Fprintf(w, "Logged in! token=%s\n", token)
	})
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		errMsg := r.URL.Query().Get("error")
		code := r.URL.Query().Get("code")
		if errMsg != "" {
			fmt.Fprintf(w, "Login error: %s (code: %s)\n", errMsg, code)
			return
		}
		fmt.Fprintln(w, `<a href="/auth/google">Sign in with Google</a>`)
	})

	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
