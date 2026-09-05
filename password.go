// Passwords, for the apps that still keep one alongside OAuth.
//
// bcrypt, at a cost that takes a noticeable fraction of a second on current
// hardware. That is the point: the cost is what makes a leaked table
// expensive to turn back into passwords.

package gologin

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordMinLength is the shortest password HashPassword will accept.
const PasswordMinLength = 8

// passwordCost is the bcrypt work factor. Twelve is roughly a quarter of a
// second on a laptop; bcrypt's own default of ten is from a slower era.
const passwordCost = 12

// ErrPasswordTooShort is returned by HashPassword for a password under
// PasswordMinLength characters.
var ErrPasswordTooShort = errors.New("go-login: password must be at least 8 characters")

// HashPassword returns a bcrypt hash of the password, suitable for storing.
func HashPassword(password string) (string, error) {
	if len([]rune(password)) < PasswordMinLength {
		return "", ErrPasswordTooShort
	}
	// bcrypt only reads the first 72 bytes and refuses longer input outright
	// in recent versions. Refusing is better than a silent truncation that
	// would let two different long passwords verify against each other.
	if len(password) > 72 {
		return "", fmt.Errorf("go-login: password must be at most 72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), passwordCost)
	if err != nil {
		return "", fmt.Errorf("go-login: hashing password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword reports whether password matches the stored hash. It never
// panics on a malformed hash; that is simply a mismatch.
func CheckPassword(hash, password string) bool {
	if hash == "" || password == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
