package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"strconv"
	"strings"
)

// Default values based on the example hash
const (
	defaultIterations = 24400
	defaultSalt       = "Prologue"
)

// VerifyPassword verifies a password against a stored hash from Nim
func VerifyPassword(password, encodedHash string) bool {
	// Split the encoded hash into its components using $ as separator
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 4 {
		fmt.Printf("Invalid hash format, expected 4 parts but got %d: %s\n", len(parts), encodedHash)
		return false
	}

	// Extract algorithm, salt, iterations, and hash
	algorithm := parts[0]
	if algorithm != "pdkdf2_sha256" { // Note: this matches your hash format with "pd" not "pb"
		fmt.Printf("Invalid algorithm: %s\n", algorithm)
		return false
	}

	salt := parts[1]

	iterations, err := strconv.Atoi(parts[2])
	if err != nil {
		fmt.Printf("Failed to parse iterations: %v\n", err)
		return false
	}

	storedHashBase64 := parts[3]

	// Decode the stored hash from base64
	storedHashBytes, err := base64.StdEncoding.DecodeString(storedHashBase64)
	if err != nil {
		fmt.Printf("Failed to decode base64 hash: %v\n", err)
		return false
	}

	// Generate hash from the provided password using the same parameters
	computedHash := pbkdf2.Key([]byte(password), []byte(salt), iterations, len(storedHashBytes), sha256.New)

	// Compare the computed hash with the stored hash (constant-time comparison)
	return subtle.ConstantTimeCompare(computedHash, storedHashBytes) == 1
}

// HashPassword creates a new password hash compatible with Nim's format
func HashPassword(password string) string {
	// Use default values
	salt := defaultSalt
	iterations := defaultIterations

	// Typical key length for PBKDF2 with SHA-256
	keyLen := 64 // This seems to be the length used based on your example

	// Generate hash
	hash := pbkdf2.Key([]byte(password), []byte(salt), iterations, keyLen, sha256.New)

	// Encode hash to base64
	encodedHash := base64.StdEncoding.EncodeToString(hash)

	// Format the complete hash string to match Nim's format
	return fmt.Sprintf("pdkdf2_sha256$%s$%d$%s", salt, iterations, encodedHash)
}
