package gologin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// oauthProvider is the internal interface for each OAuth provider.
type oauthProvider interface {
	// AuthURL returns the provider's authorisation URL with the given state.
	AuthURL(state string) string
	// Exchange trades the authorisation code for an access token.
	Exchange(ctx context.Context, code string) (accessToken string, err error)
	// UserInfo fetches the authenticated user's profile.
	UserInfo(ctx context.Context, accessToken string) (ProviderUserInfo, error)
}

// httpClient is the shared HTTP client used for token exchange and user-info
// calls. A 10-second timeout is intentionally conservative.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// ---- Google provider --------------------------------------------------------

type googleProvider struct {
	cfg *OAuthProviderConfig
}

func newGoogleProvider(cfg *OAuthProviderConfig) oauthProvider {
	return &googleProvider{cfg: cfg}
}

func (g *googleProvider) AuthURL(state string) string {
	params := url.Values{
		"client_id":     {g.cfg.ClientID},
		"redirect_uri":  {g.cfg.RedirectURL},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
		"access_type":   {"offline"},
		"prompt":        {"select_account"},
	}
	return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
}

func (g *googleProvider) Exchange(ctx context.Context, code string) (string, error) {
	data := url.Values{
		"code":          {code},
		"client_id":     {g.cfg.ClientID},
		"client_secret": {g.cfg.ClientSecret},
		"redirect_uri":  {g.cfg.RedirectURL},
		"grant_type":    {"authorization_code"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://oauth2.googleapis.com/token",
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrProviderExchange, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrProviderExchange, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: google token endpoint returned %d: %s", ErrProviderExchange, resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("%w: %w", ErrProviderExchange, err)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("%w: google returned empty access_token", ErrProviderExchange)
	}
	return result.AccessToken, nil
}

func (g *googleProvider) UserInfo(ctx context.Context, accessToken string) (ProviderUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return ProviderUserInfo{}, fmt.Errorf("%w: %w", ErrProviderUserInfo, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return ProviderUserInfo{}, fmt.Errorf("%w: %w", ErrProviderUserInfo, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return ProviderUserInfo{}, fmt.Errorf("%w: google userinfo returned %d: %s", ErrProviderUserInfo, resp.StatusCode, body)
	}

	var result struct {
		Sub        string `json:"sub"`
		Email      string `json:"email"`
		Name       string `json:"name"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
		Picture    string `json:"picture"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return ProviderUserInfo{}, fmt.Errorf("%w: %w", ErrProviderUserInfo, err)
	}
	return ProviderUserInfo{
		ProviderUserID: result.Sub,
		Email:          result.Email,
		Name:           result.Name,
		FirstName:      result.GivenName,
		LastName:       result.FamilyName,
		AvatarURL:      result.Picture,
	}, nil
}

// ---- GitHub provider --------------------------------------------------------

type githubProvider struct {
	cfg *OAuthProviderConfig
}

func newGithubProvider(cfg *OAuthProviderConfig) oauthProvider {
	return &githubProvider{cfg: cfg}
}

func (gh *githubProvider) AuthURL(state string) string {
	params := url.Values{
		"client_id":    {gh.cfg.ClientID},
		"redirect_uri": {gh.cfg.RedirectURL},
		"scope":        {"user:email"},
		"state":        {state},
	}
	return "https://github.com/login/oauth/authorize?" + params.Encode()
}

func (gh *githubProvider) Exchange(ctx context.Context, code string) (string, error) {
	data := url.Values{
		"code":          {code},
		"client_id":     {gh.cfg.ClientID},
		"client_secret": {gh.cfg.ClientSecret},
		"redirect_uri":  {gh.cfg.RedirectURL},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://github.com/login/oauth/access_token",
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrProviderExchange, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrProviderExchange, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: github token endpoint returned %d: %s", ErrProviderExchange, resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("%w: %w", ErrProviderExchange, err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("%w: github returned error: %s", ErrProviderExchange, result.Error)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("%w: github returned empty access_token", ErrProviderExchange)
	}
	return result.AccessToken, nil
}

func (gh *githubProvider) UserInfo(ctx context.Context, accessToken string) (ProviderUserInfo, error) {
	// Fetch profile
	profile, err := gh.fetchProfile(ctx, accessToken)
	if err != nil {
		return ProviderUserInfo{}, err
	}

	// GitHub may not expose the primary email in the profile; fetch separately.
	email, err := gh.fetchPrimaryEmail(ctx, accessToken)
	if err != nil {
		return ProviderUserInfo{}, err
	}
	if email == "" && profile.Email != "" {
		email = profile.Email
	}

	return ProviderUserInfo{
		ProviderUserID: fmt.Sprintf("%d", profile.ID),
		Email:          email,
		Name:           profile.Name,
		AvatarURL:      profile.AvatarURL,
	}, nil
}

type githubProfile struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (gh *githubProvider) fetchProfile(ctx context.Context, accessToken string) (githubProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/user", nil)
	if err != nil {
		return githubProfile{}, fmt.Errorf("%w: %w", ErrProviderUserInfo, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return githubProfile{}, fmt.Errorf("%w: %w", ErrProviderUserInfo, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return githubProfile{}, fmt.Errorf("%w: github /user returned %d: %s", ErrProviderUserInfo, resp.StatusCode, body)
	}

	var profile githubProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return githubProfile{}, fmt.Errorf("%w: %w", ErrProviderUserInfo, err)
	}
	return profile, nil
}

func (gh *githubProvider) fetchPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/user/emails", nil)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrProviderUserInfo, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrProviderUserInfo, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		// Non-fatal: fall back to profile email
		return "", nil
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", nil
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	// Fallback: first verified email
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}
	return "", nil
}
