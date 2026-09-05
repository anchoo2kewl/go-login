package gologin

import (
	"errors"
	"strings"
	"testing"
)

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$2a$12$") {
		t.Errorf("hash %q is not bcrypt at cost 12", hash)
	}
	if !CheckPassword(hash, "correct horse battery") {
		t.Error("the right password was refused")
	}
	if CheckPassword(hash, "correct horse batter") {
		t.Error("a wrong password was accepted")
	}
	if CheckPassword(hash, "") || CheckPassword("", "correct horse battery") || CheckPassword("not a hash", "x") {
		t.Error("an empty or malformed input was accepted")
	}

	again, _ := HashPassword("correct horse battery")
	if again == hash {
		t.Error("two hashes of one password are identical; salt is missing")
	}
}

func TestHashPasswordRefusesShortAndOverlong(t *testing.T) {
	if _, err := HashPassword("seven77"); !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("seven characters: err = %v", err)
	}
	if _, err := HashPassword("eight888"); err != nil {
		t.Errorf("eight characters refused: %v", err)
	}
	if _, err := HashPassword(strings.Repeat("a", 73)); err == nil {
		t.Error("73 bytes accepted; bcrypt would truncate or refuse")
	}
}
