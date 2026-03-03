package gologin

import (
	"fmt"
	"time"

	"go.uber.org/zap"
)

// OAuthProviderConfig holds the credentials for a single OAuth provider.
type OAuthProviderConfig struct {
	// ClientID is the OAuth application client ID.
	ClientID string
	// ClientSecret is the OAuth application client secret.
	ClientSecret string
	// RedirectURL is the full callback URL registered with the OAuth provider,
	// e.g. "https://example.com/api/auth/google/callback".
	RedirectURL string
}

// Config configures the go-login handler. Both Google and GitHub fields are
// optional; a nil pointer means that provider is disabled.
type Config struct {
	// Google OAuth provider config. Nil disables Google sign-in.
	Google *OAuthProviderConfig
	// GitHub OAuth provider config. Nil disables GitHub sign-in.
	GitHub *OAuthProviderConfig

	// SuccessURL is the frontend URL the user is redirected to after a
	// successful login/signup. The JWT token is appended as "?token=<jwt>".
	SuccessURL string
	// ErrorURL is the frontend URL the user is redirected to on failure.
	// Query parameters "error" and "code" are appended automatically.
	ErrorURL string

	// StateSecret is the HMAC key used to sign the OAuth state JWT.
	// MUST be different from JWTSecret to prevent state tokens being used as
	// access tokens.
	StateSecret string

	// JWTSecret is the HS256 signing key for the access tokens issued by
	// go-login. Must match the secret used by the consuming application's JWT
	// middleware so tokens are mutually accepted.
	JWTSecret string

	// JWTExpiry is how long the issued access token is valid. Defaults to 24h.
	JWTExpiry time.Duration

	// Logger is an optional zap.Logger. When nil a no-op logger is used.
	Logger *zap.Logger
}

// Validate checks that all required fields are populated.
func (c *Config) Validate() error {
	if c.Google == nil && c.GitHub == nil {
		return fmt.Errorf("go-login: at least one OAuth provider (Google or GitHub) must be configured")
	}
	if c.SuccessURL == "" {
		return fmt.Errorf("go-login: SuccessURL is required")
	}
	if c.ErrorURL == "" {
		return fmt.Errorf("go-login: ErrorURL is required")
	}
	if c.StateSecret == "" {
		return fmt.Errorf("go-login: StateSecret is required")
	}
	if c.JWTSecret == "" {
		return fmt.Errorf("go-login: JWTSecret is required")
	}
	if c.StateSecret == c.JWTSecret {
		return fmt.Errorf("go-login: StateSecret and JWTSecret must be different")
	}
	if c.Google != nil {
		if c.Google.ClientID == "" || c.Google.ClientSecret == "" || c.Google.RedirectURL == "" {
			return fmt.Errorf("go-login: Google provider requires ClientID, ClientSecret, and RedirectURL")
		}
	}
	if c.GitHub != nil {
		if c.GitHub.ClientID == "" || c.GitHub.ClientSecret == "" || c.GitHub.RedirectURL == "" {
			return fmt.Errorf("go-login: GitHub provider requires ClientID, ClientSecret, and RedirectURL")
		}
	}
	return nil
}

// logger returns cfg.Logger or a no-op logger.
func (c *Config) logger() *zap.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return zap.NewNop()
}

// jwtExpiry returns JWTExpiry or the default 24h.
func (c *Config) jwtExpiry() time.Duration {
	if c.JWTExpiry > 0 {
		return c.JWTExpiry
	}
	return 24 * time.Hour
}
