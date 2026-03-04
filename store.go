package gologin

import "context"

// UserStore is the interface the consuming application must implement so
// go-login can look up and create users during the OAuth callback flow.
//
// All methods must be safe for concurrent use. Returning (nil, nil) from a
// finder method signals "not found" without error.
type UserStore interface {
	// FindUserByProviderID looks up a user by the OAuth provider and the
	// provider-specific user ID (e.g. Google "sub"). Returns (nil, nil) when no
	// matching record is found.
	FindUserByProviderID(ctx context.Context, provider, providerUserID string) (*User, error)

	// FindUserByEmail looks up a user by email address. Returns (nil, nil) when
	// no matching record is found.
	FindUserByEmail(ctx context.Context, email string) (*User, error)

	// GetUserAuthProvider returns the auth provider registered for the given
	// user ID. Expected values are "google", "github", or "password".
	GetUserAuthProvider(ctx context.Context, userID int64) (string, error)

	// CreateOAuthUser creates a new user account from OAuth provider data,
	// claims the invite (if the app requires one), and records the provider link.
	// inviteCode is the raw code from the OAuth state; it may be empty if the
	// app allows invite-free OAuth sign-up.
	CreateOAuthUser(ctx context.Context, info ProviderUserInfo, provider, inviteCode string) (*User, error)

	// ValidateInviteCode checks whether the given invite code exists and is
	// still usable. Returns (nil, nil) when the code is not found or is already
	// used/expired.
	ValidateInviteCode(ctx context.Context, code string) (*InviteInfo, error)

	// LinkOAuthProvider associates a new OAuth provider with an existing user
	// account. Called when a user signs in via a provider whose email matches an
	// existing account. Should be idempotent if the provider is already linked.
	LinkOAuthProvider(ctx context.Context, userID int64, provider, providerUserID string) (*User, error)
}
