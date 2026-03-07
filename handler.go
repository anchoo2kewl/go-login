package gologin

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
)

// Handler holds the initialised configuration and store, and provides HTTP
// handler methods that can be registered directly on any router.
type Handler struct {
	cfg     *Config
	store   UserStore
	logger  *zap.Logger
	google  oauthProvider
	github  oauthProvider
}

// NewHandler validates the config and returns a ready-to-use Handler.
// Returns an error if the config is invalid.
func NewHandler(cfg *Config, store UserStore) (*Handler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("go-login: UserStore must not be nil")
	}

	h := &Handler{
		cfg:    cfg,
		store:  store,
		logger: cfg.logger(),
	}

	if cfg.Google != nil {
		h.google = newGoogleProvider(cfg.Google)
	}
	if cfg.GitHub != nil {
		h.github = newGithubProvider(cfg.GitHub)
	}

	return h, nil
}

// HandleGoogleInitiate starts the Google OAuth flow.
// Mount at: GET /api/auth/google
func (h *Handler) HandleGoogleInitiate(w http.ResponseWriter, r *http.Request) {
	if h.google == nil {
		http.Error(w, "Google sign-in is not configured", http.StatusNotFound)
		return
	}
	h.initiateFlow(w, r, "google", h.google)
}

// HandleGoogleCallback handles the Google OAuth callback.
// Mount at: GET /api/auth/google/callback
func (h *Handler) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if h.google == nil {
		http.Error(w, "Google sign-in is not configured", http.StatusNotFound)
		return
	}
	h.handleCallback(w, r, "google", h.google)
}

// HandleGithubInitiate starts the GitHub OAuth flow.
// Mount at: GET /api/auth/github/login
func (h *Handler) HandleGithubInitiate(w http.ResponseWriter, r *http.Request) {
	if h.github == nil {
		http.Error(w, "GitHub sign-in is not configured", http.StatusNotFound)
		return
	}
	h.initiateFlow(w, r, "github", h.github)
}

// HandleGithubCallback handles the GitHub OAuth callback.
// Mount at: GET /api/auth/github/login/callback
func (h *Handler) HandleGithubCallback(w http.ResponseWriter, r *http.Request) {
	if h.github == nil {
		http.Error(w, "GitHub sign-in is not configured", http.StatusNotFound)
		return
	}
	h.handleCallback(w, r, "github", h.github)
}

// ----- internal helpers -------------------------------------------------------

// initiateFlow reads an optional ?invite_code query param, builds the signed
// state JWT, and redirects to the provider's authorisation URL.
func (h *Handler) initiateFlow(w http.ResponseWriter, r *http.Request, providerName string, p oauthProvider) {
	inviteCode := r.URL.Query().Get("invite_code")

	state, err := signState(providerName, inviteCode, h.cfg.StateSecret)
	if err != nil {
		h.logger.Error("failed to sign OAuth state",
			zap.String("provider", providerName),
			zap.Error(err))
		h.redirectError(w, r, "internal error", "internal_error")
		return
	}

	http.Redirect(w, r, p.AuthURL(state), http.StatusTemporaryRedirect)
}

// handleCallback processes the provider callback following the decision tree
// described in the package documentation.
func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request, providerName string, p oauthProvider) {
	q := r.URL.Query()

	// 1. Parse and verify state JWT (CSRF check)
	stateToken := q.Get("state")
	stateProvider, inviteCode, err := parseState(stateToken, h.cfg.StateSecret)
	if err != nil {
		h.logger.Warn("invalid OAuth state", zap.String("provider", providerName), zap.Error(err))
		h.redirectError(w, r, "invalid or expired session — please try again", "invalid_state")
		return
	}
	if stateProvider != providerName {
		h.logger.Warn("OAuth state provider mismatch",
			zap.String("expected", providerName),
			zap.String("got", stateProvider))
		h.redirectError(w, r, "invalid state", "invalid_state")
		return
	}

	// Check for provider-side error
	if errParam := q.Get("error"); errParam != "" {
		h.logger.Info("OAuth provider returned error",
			zap.String("provider", providerName),
			zap.String("error", errParam))
		h.redirectError(w, r, "sign-in was cancelled or denied", "provider_error")
		return
	}

	code := q.Get("code")
	if code == "" {
		h.redirectError(w, r, "missing authorisation code", "missing_code")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// 2. Exchange authorisation code for access token
	accessToken, err := p.Exchange(ctx, code)
	if err != nil {
		h.logger.Error("OAuth token exchange failed",
			zap.String("provider", providerName),
			zap.Error(err))
		h.redirectError(w, r, "failed to complete sign-in — please try again", "exchange_failed")
		return
	}

	// 3. Fetch user info from provider
	info, err := p.UserInfo(ctx, accessToken)
	if err != nil {
		h.logger.Error("failed to fetch user info",
			zap.String("provider", providerName),
			zap.Error(err))
		h.redirectError(w, r, "failed to fetch profile from provider", "userinfo_failed")
		return
	}

	if info.Email == "" {
		h.redirectError(w, r, "provider did not return an email address", "no_email")
		return
	}

	// 4. Try to find an existing user by provider ID
	existingUser, err := h.store.FindUserByProviderID(ctx, providerName, info.ProviderUserID)
	if err != nil {
		h.logger.Error("FindUserByProviderID failed",
			zap.String("provider", providerName),
			zap.Error(err))
		h.redirectError(w, r, "database error", "internal_error")
		return
	}

	if existingUser != nil {
		// Happy path: returning user
		h.issueTokenAndRedirect(w, r, existingUser)
		return
	}

	// 5. Not found by provider ID — look up by email
	emailUser, err := h.store.FindUserByEmail(ctx, info.Email)
	if err != nil {
		h.logger.Error("FindUserByEmail failed",
			zap.String("email", info.Email),
			zap.Error(err))
		h.redirectError(w, r, "database error", "internal_error")
		return
	}

	if emailUser != nil {
		// Email matches an existing account — link this provider and sign in.
		linkedUser, err := h.store.LinkOAuthProvider(ctx, emailUser.ID, providerName, info.ProviderUserID)
		if err != nil {
			h.logger.Error("LinkOAuthProvider failed",
				zap.Int64("user_id", emailUser.ID),
				zap.String("provider", providerName),
				zap.Error(err))
			h.redirectError(w, r, "database error", "internal_error")
			return
		}
		h.logger.Info("OAuth provider linked to existing account",
			zap.String("provider", providerName),
			zap.Int64("user_id", emailUser.ID),
			zap.String("email", emailUser.Email))
		h.issueTokenAndRedirect(w, r, linkedUser)
		return
	}

	// 6. New user — check invite code
	if inviteCode == "" {
		h.redirectError(w, r, "an invite code is required to create an account", "invite_required")
		return
	}

	invite, err := h.store.ValidateInviteCode(ctx, inviteCode)
	if err != nil {
		h.logger.Error("ValidateInviteCode failed", zap.Error(err))
		h.redirectError(w, r, "database error", "internal_error")
		return
	}
	if invite == nil {
		h.redirectError(w, r, "invite code is invalid, expired, or has already been used", "invalid_invite")
		return
	}

	// 7. Create the user
	newUser, err := h.store.CreateOAuthUser(ctx, info, providerName, inviteCode)
	if err != nil {
		h.logger.Error("CreateOAuthUser failed",
			zap.String("provider", providerName),
			zap.String("email", info.Email),
			zap.Error(err))
		h.redirectError(w, r, "failed to create account — please try again", "create_user_failed")
		return
	}

	h.logger.Info("OAuth user created",
		zap.String("provider", providerName),
		zap.Int64("user_id", newUser.ID),
		zap.String("email", newUser.Email))

	h.issueTokenAndRedirect(w, r, newUser)
}

// issueTokenAndRedirect mints a JWT and redirects to SuccessURL.
func (h *Handler) issueTokenAndRedirect(w http.ResponseWriter, r *http.Request, u *User) {
	token, err := GenerateToken(u.ID, u.Email, h.cfg.JWTSecret, h.cfg.jwtExpiry())
	if err != nil {
		h.logger.Error("failed to generate JWT", zap.Int64("user_id", u.ID), zap.Error(err))
		h.redirectError(w, r, "failed to generate session token", "token_error")
		return
	}

	if h.cfg.OnLoginSuccess != nil {
		h.cfg.OnLoginSuccess(r, u.ID)
	}

	target := h.cfg.SuccessURL + "?token=" + url.QueryEscape(token)
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}

// redirectError redirects to ErrorURL with human-readable and machine-readable
// error information appended as query parameters.
func (h *Handler) redirectError(w http.ResponseWriter, r *http.Request, message, code string) {
	params := url.Values{
		"error": {message},
		"code":  {code},
	}
	http.Redirect(w, r, h.cfg.ErrorURL+"?"+params.Encode(), http.StatusTemporaryRedirect)
}
