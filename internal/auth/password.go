package auth

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// MinPasswordLen is the minimum accepted password length.
const MinPasswordLen = 8

// MaxPasswordLen is the bcrypt input limit in bytes.
const MaxPasswordLen = 72

// ErrWeakPassword is returned for passwords shorter than MinPasswordLen.
var ErrWeakPassword = errors.New("password too short")

// ErrLongPassword is returned for passwords longer than MaxPasswordLen bytes.
var ErrLongPassword = errors.New("password longer than 72 bytes")

// bcryptCost is a variable so tests can lower it.
var bcryptCost = bcrypt.DefaultCost

// HashPassword returns a bcrypt hash of pw.
func HashPassword(pw string) (string, error) {
	if len(pw) < MinPasswordLen {
		return "", ErrWeakPassword
	}
	if len(pw) > MaxPasswordLen {
		return "", ErrLongPassword
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	return string(h), err
}

// CheckPassword reports whether pw matches the bcrypt hash.
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// dummyHash is compared against when the login does not exist, so response
// time does not reveal which logins are valid.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("asi-dummy-password"), bcrypt.DefaultCost)
