package gologin

import (
	"context"
	"errors"
	"testing"
)

type stubPasskeyStore struct {
	creds []PasskeyCredential
	user  PasskeyUser
	err   error
}

func (s stubPasskeyStore) PasskeyCredentials(context.Context, int64) ([]PasskeyCredential, error) {
	return s.creds, s.err
}
func (s stubPasskeyStore) PasskeyUserByID(context.Context, int64) (PasskeyUser, error) {
	return s.user, s.err
}

func TestNewPasskeysValidatesItsConfig(t *testing.T) {
	store := stubPasskeyStore{}
	if _, err := NewPasskeys(PasskeyConfig{AppURL: "https://pool.example"}, nil); err == nil {
		t.Error("a nil store was accepted")
	}
	for _, bad := range []string{"", "not a url", "/relative"} {
		if _, err := NewPasskeys(PasskeyConfig{AppURL: bad}, store); err == nil {
			t.Errorf("AppURL %q was accepted", bad)
		}
	}
	if _, err := NewPasskeys(PasskeyConfig{AppURL: "https://pool.example"}, store); err != nil {
		t.Errorf("a good config was refused: %v", err)
	}
}

// The relying party id and origin come from one URL, and that pairing is what
// stops a credential registered here being usable elsewhere.
func TestBeginRegistrationDescribesThisSite(t *testing.T) {
	p, err := NewPasskeys(PasskeyConfig{DisplayName: "Pool", AppURL: "https://pool.example/"}, stubPasskeyStore{})
	if err != nil {
		t.Fatal(err)
	}
	opts, session, err := p.BeginRegistration(context.Background(),
		PasskeyUser{ID: 7, Email: "someone@example.com"})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if len(session) == 0 {
		t.Error("no ceremony state came back to store")
	}
	// The session must survive a round trip through storage as opaque bytes.
	if _, err := decodeSession(session); err != nil {
		t.Errorf("the ceremony state did not decode: %v", err)
	}
	if opts == nil {
		t.Error("no options for the browser")
	}
}

func TestBeginLoginAsksForNoUser(t *testing.T) {
	p, _ := NewPasskeys(PasskeyConfig{AppURL: "https://pool.example"}, stubPasskeyStore{})
	opts, session, err := p.BeginLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if opts == nil || len(session) == 0 {
		t.Error("discoverable sign-in produced nothing to work with")
	}
}

// Garbage from a browser must come back as one refusal, not a panic and not a
// message describing which check failed.
func TestFinishRejectsRubbish(t *testing.T) {
	p, _ := NewPasskeys(PasskeyConfig{AppURL: "https://pool.example"}, stubPasskeyStore{})
	_, session, _ := p.BeginRegistration(context.Background(), PasskeyUser{ID: 1, Email: "a@b.c"})

	if _, err := p.FinishRegistration(context.Background(), PasskeyUser{ID: 1}, session, []byte(`{"bad":true}`)); !errors.Is(err, ErrPasskeyRejected) {
		t.Errorf("err = %v, want ErrPasskeyRejected", err)
	}
	if _, err := p.FinishRegistration(context.Background(), PasskeyUser{ID: 1}, []byte("not json"), []byte(`{}`)); !errors.Is(err, ErrPasskeyRejected) {
		t.Errorf("unreadable ceremony state: err = %v, want ErrPasskeyRejected", err)
	}
	if _, _, err := p.FinishLogin(context.Background(), session, []byte(`{"bad":true}`)); !errors.Is(err, ErrPasskeyRejected) {
		t.Errorf("login: err = %v, want ErrPasskeyRejected", err)
	}
}

// The handle is what ties an assertion back to an account, so it has to round
// trip exactly — including for ids near the boundaries.
func TestUserHandleRoundTrips(t *testing.T) {
	for _, id := range []int64{1, 42, 1 << 31, 1<<62 - 1} {
		got, err := userIDFromHandle(UserHandle(id))
		if err != nil {
			t.Fatalf("handle for %d: %v", id, err)
		}
		if got != id {
			t.Errorf("handle for %d came back as %d", id, got)
		}
	}
	if _, err := userIDFromHandle([]byte("short")); !errors.Is(err, ErrPasskeyUnknownUser) {
		t.Errorf("a malformed handle gave %v, want ErrPasskeyUnknownUser", err)
	}
}

// Browsers refuse passkeys outside a secure context, so an app needs to know
// before it offers the option.
func TestPasskeysUsable(t *testing.T) {
	for url, want := range map[string]bool{
		"https://pool.biswas.me": true,
		"http://localhost:8080":  true,
		"http://127.0.0.1:8080":  true,
		"http://pool.example":    false,
		"":                       false,
	} {
		if got := PasskeysUsable(url); got != want {
			t.Errorf("PasskeysUsable(%q) = %v, want %v", url, got, want)
		}
	}
}
