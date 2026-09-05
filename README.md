# go-login

Sign-in for Go apps: OAuth, Clerk, passwords, a second factor, and passkeys — with your storage, not ours.

Designed to be dropped into the same apps as [go-ai](https://github.com/anchoo2kewl/go-ai),
[go-api](https://github.com/anchoo2kewl/go-api) and [go-photo](https://github.com/anchoo2kewl/go-photo).
Every part of it takes an interface over your own database and hands back plain
values to persist. Nothing here owns a table.

## What it does

- **OAuth** — Google and GitHub, with invite gating and cross-provider account linking.
- **Clerk** — verify session tokens locally against the instance JWKS, map them to your accounts, or swap them for a go-login token.
- **Passwords** — bcrypt at a cost that hurts, for the apps that still keep one.
- **Two-factor codes** — TOTP to RFC 6238, plus single-use recovery codes.
- **Passkeys** — WebAuthn registration and passwordless sign-in over [go-webauthn](https://github.com/go-webauthn/webauthn).

## Install

```
go get github.com/anchoo2kewl/go-login
```

Requires Go 1.25, which is go-webauthn's floor.

## Two-factor codes

No storage, no state — you keep the secret and the code hashes.

```go
secret, err := gologin.NewTOTPSecret()          // store it, unconfirmed
uri := gologin.TOTPURI("pool.biswas.me", user.Email, secret)  // render as a QR

// Switch the factor on only once a code proves the secret arrived, or a setup
// abandoned halfway locks somebody out of their own account.
if gologin.VerifyTOTP(secret, typed, time.Now()) {
    confirm(user)
}
```

`FormatTOTPSecret` groups it for reading off a screen, and a secret typed back
with spaces or in lower case still verifies.

**Recovery codes** are what get somebody back in when the phone is gone:

```go
codes, hashes, err := gologin.NewRecoveryCodes()  // show codes once, store hashes
...
if used, _ := store.SpendRecoveryCode(user.ID, gologin.HashRecoveryCode(typed)); used {
    signIn(user)
}
```

They use a Crockford-style alphabet — no I, L, O or U — so a code read off a
screen cannot be misread, and hashing normalises case and hyphens because that
is how people type them back.

### The parts worth knowing

The tolerance is one step either side of now. That covers a phone clock a few
seconds out, and costs a threefold widening of the guess space rather than the
elevenfold a wider window would. Candidates are compared in constant time and
the loop is not short-circuited, so the timing says nothing about which step
matched.

The implementation is checked against the RFC 6238 vectors, because if that
drifts every authenticator app in the world disagrees with you.

## Passkeys

Implement two reads. This package never writes.

```go
type PasskeyStore interface {
    PasskeyCredentials(ctx context.Context, userID int64) ([]gologin.PasskeyCredential, error)
    PasskeyUserByID(ctx context.Context, userID int64) (gologin.PasskeyUser, error)
}

pk, err := gologin.NewPasskeys(gologin.PasskeyConfig{
    DisplayName: "Pool",
    AppURL:      "https://pool.biswas.me",
}, store)
```

**Registering**, for a signed-in account:

```go
options, session, err := pk.BeginRegistration(ctx, user)
// send options to the browser; park session against this browser

cred, err := pk.FinishRegistration(ctx, user, session, responseFromBrowser)
// store cred.ID, cred.PublicKey, cred.SignCount, cred.BackedUp
```

**Signing in**, with no password and no email:

```go
options, session, err := pk.BeginLogin(ctx)

user, cred, err := pk.FinishLogin(ctx, session, responseFromBrowser)
// store cred.SignCount — the next sign-in is checked against it
```

Sign-in is discoverable: the credential carries the user handle, so the browser
offers the right passkey and the server learns who it is from the assertion.
That also means the endpoint reveals nothing about who has an account.

`ErrPasskeyCloned` comes back when an authenticator's signature counter has
gone backwards, which is what a copied credential looks like. Refusing is the
only safe answer.

`PasskeysUsable(appURL)` reports whether a browser will permit passkeys at all —
they need a secure context, so an interface can say why the option is missing
rather than offering a button that fails with no explanation.

Ceremony state comes back as opaque bytes for you to store wherever you keep
short-lived things. Putting it in a database rather than memory means a restart
mid-ceremony fails cleanly instead of mysteriously.

## OAuth

```go
h, err := gologin.NewHandler(&gologin.Config{
    Google: &gologin.OAuthProviderConfig{ClientID: ..., ClientSecret: ...},
    GitHub: &gologin.OAuthProviderConfig{ClientID: ..., ClientSecret: ...},
}, userStore)
```

`UserStore` is the interface for looking up and creating accounts during a
callback: finding by provider id or email, creating from provider data,
validating an invite, and linking a provider to an existing account.

## Clerk

Clerk signs session tokens with RS256 and publishes the keys. Verifying one
is a local operation once they are cached, so nothing here calls Clerk per
request.

```go
v, err := gologin.NewClerkVerifier(gologin.ClerkConfig{
    IssuerURL: "https://clerk.example.com",   // the Frontend API URL
})

id, err := v.Verify(ctx, sessionToken)
// id.ClerkID, id.Email, id.Name, id.Claims
```

Construction does not fetch. The keys arrive with the first token that needs
them, so an app boots when Clerk is down and fails only the requests that
depend on it. An unknown key id triggers one refresh — that is what a rotation
looks like — and then a minute's cool-down, so a stream of forged tokens cannot
become a stream of requests to Clerk. Only RS256 is accepted; a token that says
HS256 and is signed with the public key bytes is refused before its claims are
read.

Clerk's default session token carries no email. When one is missing the
verifier asks `/oauth/userinfo` with the token, unless `SkipUserInfo` is set
because you have added email to the session token's claims template.

**Mapping to an account** follows the OAuth callback's tree — found by Clerk
id, else linked to the account with the same email, else created:

```go
user, id, err := v.Resolve(ctx, sessionToken, store)
```

`ClerkUserStore` is a subset of `UserStore`, so whatever you already gave the
OAuth handler works here. Accounts are stored under provider `"clerk"`.
`ErrClerkNoEmail` comes back when there is nothing to find or create with.

**Exchange for a go-login token**, so a browser signed in with Clerk talks to
the API the same way every other session does:

```go
h, err := gologin.NewHandler(&gologin.Config{
    Clerk:     &gologin.ClerkConfig{IssuerURL: "https://clerk.example.com"},
    JWTSecret: secret,
}, store)
mux.HandleFunc("POST /api/auth/clerk/exchange", h.HandleClerkExchange)
```

It takes `{"token": "..."}` or `Authorization: Bearer`, answers
`{"token": "<jwt>", "user": {"id": ..., "email": ...}}`, and calls
`OnLoginSuccess`. A Clerk-only config needs no redirect URLs or state secret;
they belong to the OAuth dance. `h.Clerk()` returns the verifier, and
`v.Keyfunc` is a `jwt.Keyfunc` for apps that parse tokens themselves.

**Accepting more than one kind of token** is what an app in the middle of a
migration needs:

```go
auth := gologin.NewAuthenticator(gologin.AuthenticatorOptions{
    Clerk:      v,
    ClerkStore: store,
    JWTSecret:  secret,
    ExtraHS256: func(c jwt.MapClaims) (*gologin.User, error) {  // optional
        return lookup(c["sub"])                                  // the old claim shape
    },
})

mux.Handle("/api/", auth.Middleware(api))
...
user := gologin.UserFromContext(r.Context())
```

`Authenticate` reads the token's `alg` to decide which verifier to try —
Clerk for RS256, your secret for HS256 — and each verifier still checks the
algorithm itself. The middleware reads `Authorization: Bearer` or `?token=`
and answers 401 with `{"error":"invalid or expired token"}`.

## Passwords

```go
hash, err := gologin.HashPassword(typed)   // bcrypt, cost 12; ErrPasswordTooShort under 8
if gologin.CheckPassword(hash, typed) {
    signIn(user)
}
```

The cost is a noticeable fraction of a second on purpose: it is what makes a
leaked table expensive to turn back into passwords. Inputs over 72 bytes are
refused rather than silently truncated.

## License

MIT
