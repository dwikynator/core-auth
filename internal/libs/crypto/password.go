package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params holds the tuneable parameters for argon2id.
// These are stored inside the PHC-format has string, so changing them
// only affects *new* hashes - existing hashes remain verfiable.
type Argon2Params struct {
	Time    uint32 // number of iterations
	Memory  uint32 // memory in KiB
	Threads uint8  // parallelism degree
	KeyLen  uint32 // derived key length in bytes
	SaltLen uint32 // salt length in bytes
}

// DefaultArgon2Params follows the OWASP minimum recommendation:
//
// m=64 MiB, t=1, p=4 (~50ms on modern hardware)
//
// Increase Time to 3 if you can tolerate ~ 150ms per hash.
var DefaultArgon2Params = Argon2Params{
	Time:    1,
	Memory:  64 * 1024, // 64 MiB
	Threads: 4,
	KeyLen:  32,
	SaltLen: 16,
}

// HashPassword produces a PHC-format string:
//
// $argon2id$v=19$m=65536,t=1,p=4$<base64-salt>$<base64-hash>
func HashPassword(password string, p *Argon2Params) (string, error) {
	// 1. Generate a completely random salt using crypto/rand.
	// A salt ensures that two users with the password "password123"
	// get completely different hashes.
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	// 2. Do the heavy lifting. This function allocates the 64 MiB of memory,
	// mixes the password and the salt together, and crunches the math.
	hash := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	// 3. Construct the standard PHC string. We use base64 to turn the raw bytes
	// of the salt and hash into printable text we can save in Postgres.
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// ComparePassword verifies a plaintext password against a PHC-format hash.
// Returns (true, nil) on match, (false, nil) on mismatch, or an error if
// the hash string is malformed.
func ComparePassword(password, encoded string) (bool, error) {
	// 1. Break the string apart by the '$' character.
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("password: invalid hash format")
	}

	// 2. Read the "v=19" part to ensure we are using the right algorithm version.
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("password: parse version: %w", err)
	}
	if version != argon2.Version {
		return false, fmt.Errorf("password: incompatible argon2 version %d", version)
	}

	// 3. CAREFULLY read the Memory, Time, and Threads that were used to create
	// THIS specific hash. (If we change our defaults next year to 128 MiB,
	// older users can still log in because we read *their* specific parameters here).
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, fmt.Errorf("password: parse params: %w", err)
	}

	// 4. Decode the printable base64 back into raw bytes for the salt and original hash.
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("password: decode salt: %w", err)
	}
	storedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("password: decode hash: %w", err)
	}

	// 5. Take the plaintext password they just typed in, mix it with their ORIGINAL salt,
	// and run it through Argon2id using their ORIGINAL memory and time settings.
	computed := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(storedHash)))

	// 6. Compare the hash we just computed against the one stored in the DB.
	// We MUST use ConstantTimeCompare instead of `computed == storedHash`.
	// If we simply use `==`, Go will return `false` the exact millisecond it finds
	// a mismatched character. Hackers can measure these microscopic time differences
	// to "guess" the hash character by character. ConstantTimeCompare always takes
	// the exact same amount of time, protecting us from "Timing Attacks".
	return subtle.ConstantTimeCompare(storedHash, computed) == 1, nil
}
