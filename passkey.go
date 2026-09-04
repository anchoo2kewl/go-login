// Passkeys: WebAuthn registration and passwordless sign-in.
//
// The protocol work — CBOR, COSE keys, attestation and assertion verification
// — is go-webauthn's. What this adds is the shape the rest of this package
// already uses: the application keeps its own storage, hands over an interface,
// and gets back plain values to persist. Ceremony state comes back as bytes for
// the app to park wherever it parks short-lived things, so a restart mid-flow
// fails cleanly rather than mysteriously.

package gologin

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Passkey errors.
var (
	// ErrPasskeyRejected covers every way a ceremony can fail verification:
	// a bad signature, the wrong origin, a stale challenge. They are one error
	// on purpose — which check failed is for the log, not for the caller.
	ErrPasskeyRejected = errors.New("go-login: passkey was not accepted")

	// ErrPasskeyCloned means the authenticator's signature counter went
	// backwards, which is what a copied credential looks like.
	ErrPasskeyCloned = errors.New("go-login: passkey signature counter went backwards")

	// ErrPasskeyUnknownUser is returned by a store when a user handle from an
	// assertion belongs to nobody.
	ErrPasskeyUnknownUser = errors.New("go-login: no user for that passkey")
)

// PasskeyUser is the account a credential belongs to.
type PasskeyUser struct {
	ID          int64
	Email       string
	DisplayName string
}

// PasskeyCredential is one registered authenticator, in the form an
// application stores and returns.
type PasskeyCredential struct {
	// ID is the credential id. Store it as raw bytes or base64url; it comes
	// back here as bytes either way.
	ID        []byte
	PublicKey []byte
	// SignCount only ever moves forward on a genuine authenticator, which is
	// what makes a clone detectable.
	SignCount uint32
	// BackedUp is true for a credential synced to a password manager or
	// platform account rather than bound to one device.
	BackedUp        bool
	Transports      []string
	AttestationType string
}

// PasskeyStore is what the application implements.
//
// Two reads, no writes: this package never decides what to persist. Finishing
// a ceremony hands back a credential for the application to store however it
// likes.
type PasskeyStore interface {
	// PasskeyCredentials returns everything registered to one account.
	PasskeyCredentials(ctx context.Context, userID int64) ([]PasskeyCredential, error)

	// PasskeyUserByID resolves the account a user handle points at. Return
	// ErrPasskeyUnknownUser when there is none.
	PasskeyUserByID(ctx context.Context, userID int64) (PasskeyUser, error)
}

// PasskeyConfig describes the relying party — this site, as the browser sees it.
type PasskeyConfig struct {
	// DisplayName is shown in the browser's prompt.
	DisplayName string
	// AppURL is the site's public URL. The host becomes the relying party id
	// and the URL itself the permitted origin; that pairing is what stops a
	// credential registered here from being usable by a page somewhere else.
	AppURL string
	// ExtraOrigins allows additional exact origins, for a site reachable at
	// more than one address.
	ExtraOrigins []string
}

// Passkeys runs the two WebAuthn ceremonies.
type Passkeys struct {
	wa    *webauthn.WebAuthn
	store PasskeyStore
}

// NewPasskeys builds the relying party.
func NewPasskeys(cfg PasskeyConfig, store PasskeyStore) (*Passkeys, error) {
	if store == nil {
		return nil, errors.New("go-login: passkeys need a PasskeyStore")
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(cfg.AppURL), "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("go-login: passkeys need a valid AppURL, got %q", cfg.AppURL)
	}
	name := cfg.DisplayName
	if name == "" {
		name = u.Hostname()
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: name,
		RPID:          u.Hostname(),
		RPOrigins:     append([]string{u.String()}, cfg.ExtraOrigins...),
	})
	if err != nil {
		return nil, fmt.Errorf("go-login: configuring passkeys: %w", err)
	}
	return &Passkeys{wa: wa, store: store}, nil
}

// PasskeysUsable reports whether a browser will permit passkeys at this URL.
//
// They need a secure context, which the browser enforces rather than the
// server — so an interface should say why the option is missing instead of
// offering a button that fails with no explanation.
func PasskeysUsable(appURL string) bool {
	u, err := url.Parse(appURL)
	if err != nil {
		return false
	}
	return u.Scheme == "https" || u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
}

// BeginRegistration starts adding a passkey to an account.
//
// The returned session is opaque; store it against the browser that started
// the ceremony and hand it back to FinishRegistration.
func (p *Passkeys) BeginRegistration(ctx context.Context, user PasskeyUser) (options any, session []byte, err error) {
	creds, err := p.credentials(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}

	descriptors := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		descriptors = append(descriptors, c.Descriptor())
	}

	opts, sessionData, err := p.wa.BeginRegistration(passkeyUser{user: user, creds: creds},
		// Excluding what is already registered means adding the same key twice
		// fails in the browser with a clear message rather than silently.
		webauthn.WithExclusions(descriptors),
		// Preferred rather than required: a discoverable credential is what
		// makes passwordless sign-in possible, but refusing an authenticator
		// that cannot store one would exclude older hardware keys for no
		// security gain.
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("go-login: beginning passkey registration: %w", err)
	}
	blob, err := json.Marshal(sessionData)
	if err != nil {
		return nil, nil, err
	}
	return opts, blob, nil
}

// FinishRegistration verifies the browser's response and returns the
// credential to store.
func (p *Passkeys) FinishRegistration(ctx context.Context, user PasskeyUser, session, response []byte) (*PasskeyCredential, error) {
	sessionData, err := decodeSession(session)
	if err != nil {
		return nil, err
	}
	creds, err := p.credentials(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPasskeyRejected, err)
	}
	cred, err := p.wa.CreateCredential(passkeyUser{user: user, creds: creds}, *sessionData, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPasskeyRejected, err)
	}

	transports := make([]string, 0, len(parsed.Response.Transports))
	for _, t := range parsed.Response.Transports {
		transports = append(transports, string(t))
	}
	return &PasskeyCredential{
		ID:              cred.ID,
		PublicKey:       cred.PublicKey,
		SignCount:       cred.Authenticator.SignCount,
		BackedUp:        cred.Flags.BackupState,
		Transports:      transports,
		AttestationType: cred.AttestationType,
	}, nil
}

// BeginLogin starts a passwordless sign-in.
//
// No email is asked for. A discoverable credential carries the user handle, so
// the browser offers the right passkey and the server learns who it is from
// the assertion — which also means this reveals nothing about who has an
// account.
func (p *Passkeys) BeginLogin(ctx context.Context) (options any, session []byte, err error) {
	opts, sessionData, err := p.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, nil, fmt.Errorf("go-login: beginning passkey sign-in: %w", err)
	}
	blob, err := json.Marshal(sessionData)
	if err != nil {
		return nil, nil, err
	}
	return opts, blob, nil
}

// FinishLogin verifies an assertion and reports who signed in.
//
// The returned credential carries the authenticator's new signature counter;
// store it, because the next sign-in is checked against it.
func (p *Passkeys) FinishLogin(ctx context.Context, session, response []byte) (PasskeyUser, *PasskeyCredential, error) {
	var who PasskeyUser

	sessionData, err := decodeSession(session)
	if err != nil {
		return who, nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return who, nil, fmt.Errorf("%w: %v", ErrPasskeyRejected, err)
	}

	cred, err := p.wa.ValidateDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		id, err := userIDFromHandle(userHandle)
		if err != nil {
			return nil, err
		}
		user, err := p.store.PasskeyUserByID(ctx, id)
		if err != nil {
			return nil, err
		}
		creds, err := p.credentials(ctx, id)
		if err != nil {
			return nil, err
		}
		who = user
		return passkeyUser{user: user, creds: creds}, nil
	}, *sessionData, parsed)
	if err != nil {
		return who, nil, fmt.Errorf("%w: %v", ErrPasskeyRejected, err)
	}
	// A counter that has gone backwards means the credential has been copied.
	// Refusing is the only safe answer.
	if cred.Authenticator.CloneWarning {
		return who, nil, ErrPasskeyCloned
	}

	return who, &PasskeyCredential{
		ID:        cred.ID,
		PublicKey: cred.PublicKey,
		SignCount: cred.Authenticator.SignCount,
		BackedUp:  cred.Flags.BackupState,
	}, nil
}

// UserHandle is the opaque id stored on the authenticator for an account.
//
// It is the account id rather than the email, because a handle lives on the
// authenticator for the life of the credential and an email can change.
func UserHandle(userID int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(userID))
	return b[:]
}

func userIDFromHandle(handle []byte) (int64, error) {
	if len(handle) != 8 {
		return 0, ErrPasskeyUnknownUser
	}
	return int64(binary.BigEndian.Uint64(handle)), nil
}

func decodeSession(session []byte) (*webauthn.SessionData, error) {
	var data webauthn.SessionData
	if err := json.Unmarshal(session, &data); err != nil {
		return nil, fmt.Errorf("%w: unreadable ceremony state", ErrPasskeyRejected)
	}
	return &data, nil
}

func (p *Passkeys) credentials(ctx context.Context, userID int64) ([]webauthn.Credential, error) {
	stored, err := p.store.PasskeyCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		cred := webauthn.Credential{ID: c.ID, PublicKey: c.PublicKey, AttestationType: c.AttestationType}
		cred.Authenticator.SignCount = c.SignCount
		cred.Flags.BackupEligible = c.BackedUp
		cred.Flags.BackupState = c.BackedUp
		out = append(out, cred)
	}
	return out, nil
}

// passkeyUser adapts an account to what go-webauthn expects.
type passkeyUser struct {
	user  PasskeyUser
	creds []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte { return UserHandle(u.user.ID) }
func (u passkeyUser) WebAuthnName() string {
	return u.user.Email
}
func (u passkeyUser) WebAuthnDisplayName() string {
	if u.user.DisplayName != "" {
		return u.user.DisplayName
	}
	return u.user.Email
}
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }
