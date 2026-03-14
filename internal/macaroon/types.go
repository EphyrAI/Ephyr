package macaroon

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

// Size limits for serialized tokens.
const (
	MaxTokenSize = 8192
	TokenSizeWarn = 4096
	formatVersion = 0x02
)

// Sentinel errors.
var (
	ErrInvalidSignature = errors.New("macaroon: invalid signature")
	ErrMalformedToken   = errors.New("macaroon: malformed token data")
	ErrTokenTooLarge    = errors.New("macaroon: token exceeds maximum size")
	ErrUnknownCaveat    = errors.New("macaroon: unknown caveat type")
	ErrMalformedCaveat  = errors.New("macaroon: malformed caveat")
	ErrEmptyDimension   = errors.New("macaroon: empty effective set on relevant dimension")
	ErrExpired          = errors.New("macaroon: token expired")
)

// Macaroon is a bearer token with HMAC-chained caveats.
// Each caveat is an additional constraint. The HMAC chain
// makes caveat removal cryptographically impossible.
type Macaroon struct {
	location  string   // informational (e.g., "ephyr-broker")
	id        []byte   // root task ULID
	caveats   [][]byte // accumulated caveat strings
	signature [32]byte // current HMAC-SHA256 signature
}

// EffectiveEnvelope holds the reduced authorization constraints.
// Derived from accumulated caveats via the Reducer.
type EffectiveEnvelope struct {
	Targets         []string
	Roles           []string
	Services        []string
	Remotes         []string
	Methods         []string
	CanDelegate     bool
	DelegationDepth int
	ExpiresAt       time.Time
}

// TokenMetadata holds informational fields extracted from caveats.
// These do NOT participate in authorization.
type TokenMetadata struct {
	Agent       string // originating agent (first value wins)
	InitiatedBy string // identity URN (first value wins)
}

// ReducerOutput combines authorization constraints and metadata.
type ReducerOutput struct {
	Envelope EffectiveEnvelope
	Metadata TokenMetadata
}

// hmacSHA256 computes HMAC-SHA256(key, data).
func hmacSHA256(key []byte, data []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// New creates a new macaroon with the given location, identifier, and root key.
// The initial signature is HMAC-SHA256(key, id).
func New(location string, id []byte, key []byte) *Macaroon {
	m := &Macaroon{
		location: location,
		id:       make([]byte, len(id)),
	}
	copy(m.id, id)
	m.signature = hmacSHA256(key, id)
	return m
}

// AddFirstPartyCaveat appends a caveat and chains the signature.
// sig_new = HMAC-SHA256(sig_old, caveat)
func (m *Macaroon) AddFirstPartyCaveat(caveat []byte) {
	c := make([]byte, len(caveat))
	copy(c, caveat)
	m.caveats = append(m.caveats, c)
	m.signature = hmacSHA256(m.signature[:], caveat)
}

// Clone returns a deep copy of the macaroon. Modifying the clone
// does not affect the original, and vice versa.
func (m *Macaroon) Clone() *Macaroon {
	c := &Macaroon{
		location:  m.location,
		id:        make([]byte, len(m.id)),
		caveats:   make([][]byte, len(m.caveats)),
		signature: m.signature,
	}
	copy(c.id, m.id)
	for i, cav := range m.caveats {
		c.caveats[i] = make([]byte, len(cav))
		copy(c.caveats[i], cav)
	}
	return c
}

// Id returns the macaroon's identifier (root task ULID).
func (m *Macaroon) Id() []byte {
	out := make([]byte, len(m.id))
	copy(out, m.id)
	return out
}

// Location returns the informational location string.
func (m *Macaroon) Location() string {
	return m.location
}

// Signature returns the current HMAC-SHA256 signature.
func (m *Macaroon) Signature() [32]byte {
	return m.signature
}

// Caveats returns a copy of the caveat list.
func (m *Macaroon) Caveats() [][]byte {
	out := make([][]byte, len(m.caveats))
	for i, c := range m.caveats {
		out[i] = make([]byte, len(c))
		copy(out[i], c)
	}
	return out
}

// Verify recomputes the HMAC chain from the root key and identifier.
// If the final signature matches, it returns the caveats as strings.
// Otherwise it returns ErrInvalidSignature.
func (m *Macaroon) Verify(key []byte) ([]string, error) {
	sig := hmacSHA256(key, m.id)
	for _, c := range m.caveats {
		sig = hmacSHA256(sig[:], c)
	}
	if !hmac.Equal(sig[:], m.signature[:]) {
		return nil, ErrInvalidSignature
	}
	caveats := make([]string, len(m.caveats))
	for i, c := range m.caveats {
		caveats[i] = string(c)
	}
	return caveats, nil
}

// MarshalBinary serializes the macaroon into a compact binary format.
//
// Format:
//
//	[1 byte: version=0x02]
//	[4 bytes: id_len][id_len bytes: id]
//	[4 bytes: location_len][location_len bytes: location]
//	[4 bytes: num_caveats]
//	  [4 bytes: caveat_len][caveat_len bytes: caveat] (repeated)
//	[32 bytes: signature]
func (m *Macaroon) MarshalBinary() ([]byte, error) {
	// Calculate total size.
	size := 1 // version
	size += 4 + len(m.id)
	size += 4 + len(m.location)
	size += 4 // num_caveats
	for _, c := range m.caveats {
		size += 4 + len(c)
	}
	size += 32 // signature

	if size > MaxTokenSize {
		return nil, ErrTokenTooLarge
	}

	buf := make([]byte, size)
	offset := 0

	// Version.
	buf[offset] = formatVersion
	offset++

	// Id.
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(m.id)))
	offset += 4
	copy(buf[offset:], m.id)
	offset += len(m.id)

	// Location.
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(m.location)))
	offset += 4
	copy(buf[offset:], m.location)
	offset += len(m.location)

	// Caveats.
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(m.caveats)))
	offset += 4
	for _, c := range m.caveats {
		binary.BigEndian.PutUint32(buf[offset:], uint32(len(c)))
		offset += 4
		copy(buf[offset:], c)
		offset += len(c)
	}

	// Signature.
	copy(buf[offset:], m.signature[:])

	return buf, nil
}

// UnmarshalBinary deserializes a macaroon from the binary format.
func (m *Macaroon) UnmarshalBinary(data []byte) error {
	if len(data) > MaxTokenSize {
		return ErrTokenTooLarge
	}
	if len(data) < 1 {
		return ErrMalformedToken
	}

	offset := 0

	// Version.
	if data[offset] != formatVersion {
		return ErrMalformedToken
	}
	offset++

	// Id.
	if offset+4 > len(data) {
		return ErrMalformedToken
	}
	idLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	if offset+idLen > len(data) || idLen < 0 {
		return ErrMalformedToken
	}
	m.id = make([]byte, idLen)
	copy(m.id, data[offset:offset+idLen])
	offset += idLen

	// Location.
	if offset+4 > len(data) {
		return ErrMalformedToken
	}
	locLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	if offset+locLen > len(data) || locLen < 0 {
		return ErrMalformedToken
	}
	m.location = string(data[offset : offset+locLen])
	offset += locLen

	// Caveats.
	if offset+4 > len(data) {
		return ErrMalformedToken
	}
	numCaveats := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	// Sanity check: each caveat needs at least 4 bytes for its length prefix.
	if numCaveats < 0 || numCaveats > (len(data)-offset)/4 {
		return ErrMalformedToken
	}

	m.caveats = make([][]byte, numCaveats)
	for i := 0; i < numCaveats; i++ {
		if offset+4 > len(data) {
			return ErrMalformedToken
		}
		cavLen := int(binary.BigEndian.Uint32(data[offset:]))
		offset += 4
		if offset+cavLen > len(data) || cavLen < 0 {
			return ErrMalformedToken
		}
		m.caveats[i] = make([]byte, cavLen)
		copy(m.caveats[i], data[offset:offset+cavLen])
		offset += cavLen
	}

	// Signature.
	if offset+32 > len(data) {
		return ErrMalformedToken
	}
	copy(m.signature[:], data[offset:offset+32])
	offset += 32

	// Must have consumed all bytes.
	if offset != len(data) {
		return ErrMalformedToken
	}

	return nil
}
