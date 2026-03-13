package token

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Crockford Base32 encoding alphabet (excludes I, L, O, U).
const crockfordBase32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// crockfordDecode maps ASCII characters to their Crockford Base32 value.
// Returns -1 for invalid characters.
var crockfordDecode [256]int8

func init() {
	for i := range crockfordDecode {
		crockfordDecode[i] = -1
	}
	for i, c := range crockfordBase32 {
		crockfordDecode[c] = int8(i)
		// Also accept lowercase.
		if c >= 'A' && c <= 'Z' {
			crockfordDecode[c+32] = int8(i)
		}
	}
}

// NewULID generates a new ULID (Universally Unique Lexicographically Sortable Identifier).
// Format: 26 characters of Crockford Base32 encoding.
// Structure: 48-bit Unix millisecond timestamp (10 chars) + 80-bit crypto random (16 chars).
func NewULID() string {
	now := time.Now()
	return newULIDAt(now)
}

// newULIDAt generates a ULID with a specific timestamp (for testing).
func newULIDAt(t time.Time) string {
	ms := uint64(t.UnixMilli())

	// 10 bytes for randomness (80 bits).
	var randomBytes [10]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		panic(fmt.Sprintf("token: failed to read crypto/rand: %v", err))
	}

	// Encode: 6 bytes timestamp + 10 bytes random = 16 bytes total.
	// ULID is 128 bits = 26 Crockford Base32 characters.
	var ulid [26]byte

	// Encode timestamp (48 bits = 10 base32 chars, most significant first).
	ulid[0] = crockfordBase32[(ms>>45)&0x1F]
	ulid[1] = crockfordBase32[(ms>>40)&0x1F]
	ulid[2] = crockfordBase32[(ms>>35)&0x1F]
	ulid[3] = crockfordBase32[(ms>>30)&0x1F]
	ulid[4] = crockfordBase32[(ms>>25)&0x1F]
	ulid[5] = crockfordBase32[(ms>>20)&0x1F]
	ulid[6] = crockfordBase32[(ms>>15)&0x1F]
	ulid[7] = crockfordBase32[(ms>>10)&0x1F]
	ulid[8] = crockfordBase32[(ms>>5)&0x1F]
	ulid[9] = crockfordBase32[ms&0x1F]

	// Encode randomness (80 bits = 16 base32 chars).
	// Pack into a uint64 + uint16 for easier bit manipulation.
	rHi := binary.BigEndian.Uint64(randomBytes[0:8])
	rLo := uint64(binary.BigEndian.Uint16(randomBytes[8:10]))

	// Combined 80 bits: rHi has upper 64, rLo has lower 16.
	// We need 16 base32 chars = 80 bits.
	// Char 10: bits 79-75 (top 5 of rHi)
	ulid[10] = crockfordBase32[(rHi>>59)&0x1F]
	ulid[11] = crockfordBase32[(rHi>>54)&0x1F]
	ulid[12] = crockfordBase32[(rHi>>49)&0x1F]
	ulid[13] = crockfordBase32[(rHi>>44)&0x1F]
	ulid[14] = crockfordBase32[(rHi>>39)&0x1F]
	ulid[15] = crockfordBase32[(rHi>>34)&0x1F]
	ulid[16] = crockfordBase32[(rHi>>29)&0x1F]
	ulid[17] = crockfordBase32[(rHi>>24)&0x1F]
	ulid[18] = crockfordBase32[(rHi>>19)&0x1F]
	ulid[19] = crockfordBase32[(rHi>>14)&0x1F]
	ulid[20] = crockfordBase32[(rHi>>9)&0x1F]
	ulid[21] = crockfordBase32[(rHi>>4)&0x1F]
	// Char 22: bits 3-0 of rHi + bit 15 of rLo
	ulid[22] = crockfordBase32[((rHi&0x0F)<<1)|((rLo>>15)&0x01)]
	ulid[23] = crockfordBase32[(rLo>>10)&0x1F]
	ulid[24] = crockfordBase32[(rLo>>5)&0x1F]
	ulid[25] = crockfordBase32[rLo&0x1F]

	return string(ulid[:])
}

// ULIDTime extracts the timestamp from a ULID string.
// Returns the zero time if the ULID is invalid.
func ULIDTime(id string) time.Time {
	if len(id) != 26 {
		return time.Time{}
	}

	// Decode the first 10 characters as the 48-bit timestamp.
	var ms uint64
	for i := 0; i < 10; i++ {
		v := crockfordDecode[id[i]]
		if v < 0 {
			return time.Time{}
		}
		ms = (ms << 5) | uint64(v)
	}

	return time.UnixMilli(int64(ms))
}

// ValidateULID checks if a string is a valid 26-character Crockford Base32 ULID.
func ValidateULID(id string) bool {
	if len(id) != 26 {
		return false
	}
	for i := 0; i < 26; i++ {
		if crockfordDecode[id[i]] < 0 {
			return false
		}
	}
	// Check that the timestamp portion doesn't overflow 48 bits.
	// Max timestamp char at position 0 is '7' (value 7), since 8<<45 > 2^48.
	upper := strings.ToUpper(id)
	if upper[0] > '7' {
		return false
	}
	return true
}
