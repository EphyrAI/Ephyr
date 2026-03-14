package macaroon

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Minter creates macaroon tokens for tasks.
type Minter struct {
	keyStore *RootKeyStore
	location string // "ephyr-broker"
}

// NewMinter creates a new Minter backed by the given RootKeyStore.
func NewMinter(keyStore *RootKeyStore) *Minter {
	return &Minter{
		keyStore: keyStore,
		location: "ephyr-broker",
	}
}

// MintRoot creates a new root task macaroon.
// The macaroon Id is the rootTaskID. Caveats are derived from the envelope.
func (m *Minter) MintRoot(rootTaskID string, agent string, initiatedBy string,
	env EffectiveEnvelope) (*Macaroon, error) {

	// 1. Generate root key via keyStore.
	key, err := m.keyStore.Generate(rootTaskID, env.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("minter: %w", err)
	}

	// 2. Create macaroon.
	mac := New(m.location, []byte(rootTaskID), key[:])

	// 3. Add caveats in specified order.
	addEnvelopeCaveats(mac, agent, initiatedBy, env)

	// 4. Check serialized size.
	if err := checkSize(mac); err != nil {
		return nil, err
	}

	return mac, nil
}

// MintDelegated creates a child macaroon by cloning the parent and adding
// narrowing caveats. The HMAC chain proves caveat accumulation.
func (m *Minter) MintDelegated(parent *Macaroon, childEnv EffectiveEnvelope) (*Macaroon, error) {
	// 1. Clone the parent macaroon.
	child := parent.Clone()

	// 2. Add narrowing caveats from child's envelope.
	// For delegated tokens, agent and initiated_by are not re-added
	// (they are metadata that uses first-value-wins from the root).
	addDelegationCaveats(child, childEnv)

	// 3. Check serialized size.
	if err := checkSize(child); err != nil {
		return nil, err
	}

	return child, nil
}

// addEnvelopeCaveats adds all caveats from an envelope to a macaroon (root minting).
func addEnvelopeCaveats(mac *Macaroon, agent string, initiatedBy string, env EffectiveEnvelope) {
	// agent
	mac.AddFirstPartyCaveat([]byte("agent = " + agent))

	// initiated_by
	mac.AddFirstPartyCaveat([]byte("initiated_by = " + initiatedBy))

	// expires_before
	mac.AddFirstPartyCaveat([]byte("expires_before = " + env.ExpiresAt.Format(time.RFC3339)))

	// target IN [...] (only if non-empty)
	if len(env.Targets) > 0 {
		mac.AddFirstPartyCaveat([]byte("target IN [" + strings.Join(env.Targets, ",") + "]"))
	}

	// role IN [...] (only if non-empty)
	if len(env.Roles) > 0 {
		mac.AddFirstPartyCaveat([]byte("role IN [" + strings.Join(env.Roles, ",") + "]"))
	}

	// service IN [...] (only if non-empty)
	if len(env.Services) > 0 {
		mac.AddFirstPartyCaveat([]byte("service IN [" + strings.Join(env.Services, ",") + "]"))
	}

	// remote IN [...] (only if non-empty)
	if len(env.Remotes) > 0 {
		mac.AddFirstPartyCaveat([]byte("remote IN [" + strings.Join(env.Remotes, ",") + "]"))
	}

	// method IN [...] (only if non-empty)
	if len(env.Methods) > 0 {
		mac.AddFirstPartyCaveat([]byte("method IN [" + strings.Join(env.Methods, ",") + "]"))
	}

	// can_delegate
	mac.AddFirstPartyCaveat([]byte("can_delegate = " + strconv.FormatBool(env.CanDelegate)))

	// delegation_depth (only if CanDelegate)
	if env.CanDelegate {
		mac.AddFirstPartyCaveat([]byte("delegation_depth <= " + strconv.Itoa(env.DelegationDepth)))
	}
}

// addDelegationCaveats adds narrowing caveats for a delegated child token.
func addDelegationCaveats(mac *Macaroon, env EffectiveEnvelope) {
	// expires_before (always present — child may have tighter expiry)
	mac.AddFirstPartyCaveat([]byte("expires_before = " + env.ExpiresAt.Format(time.RFC3339)))

	// target IN [...] (only if non-empty)
	if len(env.Targets) > 0 {
		mac.AddFirstPartyCaveat([]byte("target IN [" + strings.Join(env.Targets, ",") + "]"))
	}

	// role IN [...] (only if non-empty)
	if len(env.Roles) > 0 {
		mac.AddFirstPartyCaveat([]byte("role IN [" + strings.Join(env.Roles, ",") + "]"))
	}

	// service IN [...] (only if non-empty)
	if len(env.Services) > 0 {
		mac.AddFirstPartyCaveat([]byte("service IN [" + strings.Join(env.Services, ",") + "]"))
	}

	// remote IN [...] (only if non-empty)
	if len(env.Remotes) > 0 {
		mac.AddFirstPartyCaveat([]byte("remote IN [" + strings.Join(env.Remotes, ",") + "]"))
	}

	// method IN [...] (only if non-empty)
	if len(env.Methods) > 0 {
		mac.AddFirstPartyCaveat([]byte("method IN [" + strings.Join(env.Methods, ",") + "]"))
	}

	// can_delegate
	mac.AddFirstPartyCaveat([]byte("can_delegate = " + strconv.FormatBool(env.CanDelegate)))

	// delegation_depth (only if CanDelegate)
	if env.CanDelegate {
		mac.AddFirstPartyCaveat([]byte("delegation_depth <= " + strconv.Itoa(env.DelegationDepth)))
	}
}

// checkSize verifies the macaroon does not exceed MaxTokenSize when serialized.
func checkSize(mac *Macaroon) error {
	_, err := mac.MarshalBinary()
	if err != nil {
		return fmt.Errorf("minter: %w", err)
	}
	return nil
}
