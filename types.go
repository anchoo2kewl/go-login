package gologin

import "time"

// User is the minimal user representation returned from the store and used
// when issuing JWT tokens. Consuming apps typically embed or extend this.
type User struct {
	ID    int64
	Email string
}

// ProviderUserInfo contains the normalised profile data fetched from an OAuth
// provider after a successful token exchange.
type ProviderUserInfo struct {
	// ProviderUserID is the unique identifier the provider assigns this user
	// (e.g. Google "sub" claim, GitHub numeric user id as string).
	ProviderUserID string
	// Email is the primary email address as reported by the provider.
	Email string
	// Name is the display name reported by the provider (may be empty).
	Name string
	// FirstName is the given name if the provider supplies it separately.
	FirstName string
	// LastName is the family name if the provider supplies it separately.
	LastName string
	// AvatarURL is the profile picture URL (optional).
	AvatarURL string
}

// InviteInfo is the result of validating an invite code. The consuming app
// returns this from UserStore.ValidateInviteCode; its contents are opaque to
// go-login (only used to distinguish valid from invalid).
type InviteInfo struct {
	// Code is the raw invite code that was validated.
	Code string
	// InviterName is an optional human-readable name of the inviter.
	InviterName string
	// ExpiresAt is the expiry time of the invite (zero value means no expiry).
	ExpiresAt time.Time
}
