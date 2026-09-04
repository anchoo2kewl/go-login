package gologin

import (
	"strings"
	"testing"
	"time"
)

// The vectors from RFC 6238 appendix B, for the SHA-1 20-byte secret
// "12345678901234567890". If this drifts, every authenticator app in the world
// disagrees with us.
func TestCodeMatchesRFC6238(t *testing.T) {
	secret := base32NoPad.EncodeToString([]byte("12345678901234567890"))
	for _, tc := range []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	} {
		got, err := TOTPCode(secret, time.Unix(tc.unix, 0).UTC())
		if err != nil {
			t.Fatalf("TOTPCode(%d): %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("Code at %d = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestVerifyAcceptsOneTOTPStepEitherSide(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	for _, offset := range []time.Duration{-TOTPStep, 0, TOTPStep} {
		code, _ := TOTPCode(secret, now.Add(offset))
		if !VerifyTOTP(secret, code, now) {
			t.Errorf("a code %v away was rejected; a clock a few seconds out must still work", offset)
		}
	}
	// Two steps is 60 seconds. Accepting that widens the guess space for no
	// practical gain.
	for _, offset := range []time.Duration{-2 * TOTPStep, 2 * TOTPStep} {
		code, _ := TOTPCode(secret, now.Add(offset))
		if VerifyTOTP(secret, code, now) {
			t.Errorf("a code %v away was accepted; the window is too wide", offset)
		}
	}
}

func TestVerifyRejectsRubbish(t *testing.T) {
	secret, _ := NewTOTPSecret()
	now := time.Now()
	valid, _ := TOTPCode(secret, now)

	for _, bad := range []string{"", "12345", "1234567", "abcdef", valid + "0"} {
		if VerifyTOTP(secret, bad, now) {
			t.Errorf("Verify accepted %q", bad)
		}
	}
	// A different secret's code for the same moment must not work.
	other, _ := NewTOTPSecret()
	otherCode, _ := TOTPCode(other, now)
	if otherCode != valid && VerifyTOTP(secret, otherCode, now) {
		t.Error("a code from a different secret was accepted")
	}
}

// A secret is read off a screen and typed into a phone, so the spacing the
// interface adds for legibility must not break it.
func TestSecretSurvivesBeingTypedByHand(t *testing.T) {
	secret, _ := NewTOTPSecret()
	now := time.Now()
	code, _ := TOTPCode(secret, now)

	if !VerifyTOTP(FormatTOTPSecret(secret), code, now) {
		t.Error("the spaced form of the secret did not verify")
	}
	if !VerifyTOTP(strings.ToLower(secret), code, now) {
		t.Error("the lower-case form of the secret did not verify")
	}
}

func TestURICarriesWhatAnAppNeeds(t *testing.T) {
	uri := TOTPURI("Pool", "someone@example.com", "ABCD")
	for _, want := range []string{"otpauth://totp/", "secret=ABCD", "issuer=Pool", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI %q is missing %q", uri, want)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount || len(hashes) != RecoveryCodeCount {
		t.Fatalf("got %d codes and %d hashes, want %d of each", len(codes), len(hashes), RecoveryCodeCount)
	}

	seen := map[string]bool{}
	for i, code := range codes {
		if seen[code] {
			t.Errorf("duplicate code %q", code)
		}
		seen[code] = true
		if HashRecoveryCode(code) != hashes[i] {
			t.Errorf("code %q does not hash to its stored hash", code)
		}
		// Typed back without the hyphen, or in lower case, it still has to work.
		if HashRecoveryCode(strings.ToLower(strings.ReplaceAll(code, "-", ""))) != hashes[i] {
			t.Errorf("code %q did not match when typed without its hyphen", code)
		}
		if strings.ContainsAny(code, "ILOU") {
			t.Errorf("code %q contains a character that is easily misread", code)
		}
	}
}
