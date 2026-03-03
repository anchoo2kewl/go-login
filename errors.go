package gologin

import "errors"

// Sentinel errors returned by the package.
var (
	// ErrWrongProvider is returned when a user with the given email exists but
	// registered with a different auth provider.
	ErrWrongProvider = errors.New("go-login: email registered with a different provider")

	// ErrInviteRequired is returned when no invite code is present and the
	// consuming app requires one for new user registration.
	ErrInviteRequired = errors.New("go-login: invite code required for new users")

	// ErrInviteInvalid is returned when the invite code is invalid, expired, or
	// already used.
	ErrInviteInvalid = errors.New("go-login: invite code is invalid, expired, or already used")

	// ErrProviderExchange is returned when the OAuth token exchange fails.
	ErrProviderExchange = errors.New("go-login: failed to exchange OAuth code for token")

	// ErrProviderUserInfo is returned when fetching the user profile from the
	// OAuth provider fails.
	ErrProviderUserInfo = errors.New("go-login: failed to fetch user info from provider")

	// ErrStateInvalid is returned when the OAuth state parameter fails
	// verification (CSRF check failed or state expired).
	ErrStateInvalid = errors.New("go-login: invalid or expired OAuth state")

	// ErrUnsupportedProvider is returned when an unrecognised provider name is
	// used in a request.
	ErrUnsupportedProvider = errors.New("go-login: unsupported OAuth provider")
)
