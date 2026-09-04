// Second factor: time-based one-time codes to RFC 6238, and the recovery codes
// that get somebody back in when the phone with the authenticator on it is
// lost or replaced.
//
// TOTP is small enough to implement directly and worth keeping legible: HMAC
// over a counter, truncated to six digits. The parts that are easy to get
// wrong — the tolerance window, and comparing in constant time — are the parts
// commented here.
//
// Nothing here touches storage. The secret and the code hashes are the
// application's to keep, the same way the OAuth side leaves users to a
// UserStore.

package gologin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTPStep is the code's lifetime. Thirty seconds is what every authenticator app
// assumes; it is not really configurable in practice.
const TOTPStep = 30 * time.Second

// TOTPDigits is how many digits a code has.
const TOTPDigits = 6

// skew is how many steps either side of now are accepted.
//
// One. That covers a phone clock a few seconds out and a person typing the
// code as it rolls over, and it costs a threefold widening of the guess space
// rather than the elevenfold a wider window would.
const skew = 1

// secretBytes is the shared secret's length. Twenty bytes matches the SHA-1
// block the algorithm uses and is what authenticator apps expect.
const secretBytes = 20

// base32NoPad is the encoding authenticator apps read.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret mints a shared secret, base32 encoded.
func NewTOTPSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("go-login: reading randomness: %w", err)
	}
	return base32NoPad.EncodeToString(buf), nil
}

// TOTPURI builds the otpauth:// URL an authenticator app scans.
//
// The issuer appears twice on purpose: once as a label prefix for older apps,
// once as a parameter for everything since. Apps that read both expect them to
// agree, and one that reads neither shows the account name alone.
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(TOTPDigits))
	q.Set("period", fmt.Sprint(int(TOTPStep.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPCode computes the code for one moment.
func TOTPCode(secret string, at time.Time) (string, error) {
	key, err := base32NoPad.DecodeString(normaliseSecret(secret))
	if err != nil {
		return "", fmt.Errorf("go-login: TOTP secret is not valid base32: %w", err)
	}
	counter := uint64(at.UTC().Unix()) / uint64(TOTPStep.Seconds())

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation, RFC 4226 §5.3: the low nibble of the last byte picks
	// where to read the four-byte window from.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < TOTPDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", TOTPDigits, value%mod), nil
}

// VerifyTOTP reports whether code is valid for the secret around now.
//
// Every candidate is compared in constant time and the loop is not
// short-circuited, so the time this takes says nothing about which step
// matched or how much of the code was right.
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != TOTPDigits {
		return false
	}
	var matched int
	for step := -skew; step <= skew; step++ {
		candidate, err := TOTPCode(secret, now.Add(time.Duration(step)*TOTPStep))
		if err != nil {
			return false
		}
		matched |= subtle.ConstantTimeCompare([]byte(candidate), []byte(code))
	}
	return matched == 1
}

// normaliseSecret makes a secret typed by hand acceptable: apps display it in spaced
// groups and in either case.
func normaliseSecret(secret string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(secret))
}

// FormatTOTPSecret groups a secret for reading off a screen, for somebody whose
// authenticator cannot scan a code.
func FormatTOTPSecret(secret string) string {
	var out strings.Builder
	for i, r := range secret {
		if i > 0 && i%4 == 0 {
			out.WriteByte(' ')
		}
		out.WriteRune(r)
	}
	return out.String()
}

// ── Recovery codes ───────────────────────────────────────────────────────

// RecoveryCodeCount is how many are issued at a time.
const RecoveryCodeCount = 10

// NewRecoveryCodes mints a fresh set, returning the codes to show once and the
// hashes to store.
//
// They are compared by equality rather than recomputed, so only hashes are
// kept — and being 40 bits of randomness each, a plain SHA-256 is right for
// the same reason it is right for an API key.
func NewRecoveryCodes() (codes []string, hashes []string, err error) {
	// Crockford-style: no I, L, O or U, so a code read off a screen and typed
	// under pressure cannot be misread.
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := 0; i < RecoveryCodeCount; i++ {
		buf := make([]byte, 10)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, fmt.Errorf("go-login: reading randomness: %w", err)
		}
		out := make([]byte, len(buf))
		for i, b := range buf {
			out[i] = alphabet[int(b)%len(alphabet)]
		}
		code := string(out[:5]) + "-" + string(out[5:])
		codes = append(codes, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return codes, hashes, nil
}

// HashRecoveryCode normalises and hashes one code, so the same code typed with
// or without its hyphen, in either case, matches what was stored.
func HashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(normaliseSecret(code)))
	return hex.EncodeToString(sum[:])
}
