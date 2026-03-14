package macaroon

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkMintRoot(b *testing.B) {
	ks := NewRootKeyStore()
	m := NewMinter(ks)
	env := EffectiveEnvelope{
		Targets:         []string{"host1", "host2", "host3"},
		Roles:           []string{"read", "operator"},
		Services:        []string{"grafana", "portainer", "github"},
		Remotes:         []string{"demo-tools"},
		Methods:         []string{"GET", "POST", "PUT", "DELETE"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Now().Add(30 * time.Minute),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("bench-root-%d", i)
		_, err := m.MintRoot(id, "agent", "ephyr:local:uid:1000", env)
		if err != nil {
			b.Fatalf("MintRoot: %v", err)
		}
		ks.Delete(id) // cleanup to avoid unbounded memory growth
	}
}

func BenchmarkMintDelegated(b *testing.B) {
	ks := NewRootKeyStore()
	m := NewMinter(ks)
	env := EffectiveEnvelope{
		Targets:         []string{"host1", "host2"},
		Roles:           []string{"read", "operator"},
		Services:        []string{"grafana"},
		Methods:         []string{"GET", "POST"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Now().Add(30 * time.Minute),
	}
	parent, err := m.MintRoot("bench-parent", "agent", "ephyr:local:uid:1000", env)
	if err != nil {
		b.Fatalf("MintRoot: %v", err)
	}

	childEnv := EffectiveEnvelope{
		Targets:         []string{"host1"},
		Roles:           []string{"read"},
		Services:        []string{"grafana"},
		Methods:         []string{"GET"},
		CanDelegate:     false,
		ExpiresAt:       time.Now().Add(10 * time.Minute),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := m.MintDelegated(parent, childEnv)
		if err != nil {
			b.Fatalf("MintDelegated: %v", err)
		}
	}
}

func BenchmarkVerifyRoot(b *testing.B) {
	ks := NewRootKeyStore()
	m := NewMinter(ks)
	v := NewVerifier(ks)
	env := EffectiveEnvelope{
		Targets:         []string{"host1", "host2"},
		Roles:           []string{"read", "operator"},
		Services:        []string{"grafana", "portainer"},
		Methods:         []string{"GET", "POST"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Now().Add(30 * time.Minute),
	}
	mac, err := m.MintRoot("bench-verify", "agent", "ephyr:local:uid:1000", env)
	if err != nil {
		b.Fatalf("MintRoot: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := v.Verify(mac)
		if err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}

func BenchmarkVerifyDelegationChain5Deep(b *testing.B) {
	ks := NewRootKeyStore()
	m := NewMinter(ks)
	v := NewVerifier(ks)

	env := EffectiveEnvelope{
		Targets:         []string{"h1", "h2", "h3", "h4", "h5"},
		Roles:           []string{"read", "operator"},
		Services:        []string{"s1", "s2", "s3"},
		Methods:         []string{"GET", "POST", "PUT"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Now().Add(30 * time.Minute),
	}

	current, err := m.MintRoot("bench-chain", "agent", "ephyr:local:uid:1000", env)
	if err != nil {
		b.Fatalf("MintRoot: %v", err)
	}
	for depth := 1; depth <= 5; depth++ {
		targetsEnd := len(env.Targets) - depth
		if targetsEnd < 1 {
			targetsEnd = 1
		}
		childEnv := EffectiveEnvelope{
			Targets:         env.Targets[:targetsEnd],
			Roles:           []string{"read"},
			Services:        env.Services[:1],
			Methods:         []string{"GET"},
			CanDelegate:     depth < 5,
			DelegationDepth: 5 - depth,
			ExpiresAt:       time.Now().Add(time.Duration(30-depth*5) * time.Minute),
		}
		current, err = m.MintDelegated(current, childEnv)
		if err != nil {
			b.Fatalf("MintDelegated depth %d: %v", depth, err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := v.Verify(current)
		if err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}

func BenchmarkReduce(b *testing.B) {
	caveats := []string{
		"agent = claude",
		"initiated_by = ephyr:local:uid:1000",
		"expires_before = 2026-12-31T23:59:59Z",
		"target IN [host1,host2,host3]",
		"role IN [read,operator]",
		"service IN [grafana,portainer]",
		"remote IN [demo-tools]",
		"method IN [GET,POST,PUT,DELETE]",
		"can_delegate = true",
		"delegation_depth <= 5",
		// Delegation hop caveats
		"target IN [host1,host2]",
		"role IN [read]",
		"service IN [grafana]",
		"method IN [GET,POST]",
		"can_delegate = false",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Reduce(caveats)
		if err != nil {
			b.Fatalf("Reduce: %v", err)
		}
	}
}

func BenchmarkMarshalUnmarshal(b *testing.B) {
	ks := NewRootKeyStore()
	m := NewMinter(ks)
	env := EffectiveEnvelope{
		Targets:         []string{"host1", "host2"},
		Roles:           []string{"read", "operator"},
		Services:        []string{"grafana"},
		Methods:         []string{"GET"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Now().Add(30 * time.Minute),
	}
	mac, err := m.MintRoot("bench-marshal", "agent", "ephyr:local:uid:1000", env)
	if err != nil {
		b.Fatalf("MintRoot: %v", err)
	}
	data, err := mac.MarshalBinary()
	if err != nil {
		b.Fatalf("MarshalBinary: %v", err)
	}

	b.Run("Marshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := mac.MarshalBinary()
			if err != nil {
				b.Fatalf("MarshalBinary: %v", err)
			}
		}
	})

	b.Run("Unmarshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var m2 Macaroon
			if err := m2.UnmarshalBinary(data); err != nil {
				b.Fatalf("UnmarshalBinary: %v", err)
			}
		}
	})
}

func BenchmarkClone(b *testing.B) {
	ks := NewRootKeyStore()
	m := NewMinter(ks)
	env := EffectiveEnvelope{
		Targets:         []string{"host1", "host2", "host3"},
		Roles:           []string{"read", "operator"},
		Services:        []string{"grafana", "portainer", "github"},
		Remotes:         []string{"demo-tools"},
		Methods:         []string{"GET", "POST", "PUT", "DELETE"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Now().Add(30 * time.Minute),
	}
	mac, err := m.MintRoot("bench-clone", "agent", "ephyr:local:uid:1000", env)
	if err != nil {
		b.Fatalf("MintRoot: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mac.Clone()
	}
}

func BenchmarkFullMintVerifyCycle(b *testing.B) {
	ks := NewRootKeyStore()
	m := NewMinter(ks)
	v := NewVerifier(ks)
	env := EffectiveEnvelope{
		Targets:         []string{"host1", "host2", "host3"},
		Roles:           []string{"read", "operator"},
		Services:        []string{"grafana", "portainer", "github"},
		Remotes:         []string{"demo-tools"},
		Methods:         []string{"GET", "POST", "PUT", "DELETE"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Now().Add(30 * time.Minute),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("bench-cycle-%d", i)
		mac, err := m.MintRoot(id, "agent", "ephyr:local:uid:1000", env)
		if err != nil {
			b.Fatalf("MintRoot: %v", err)
		}
		_, err = v.Verify(mac)
		if err != nil {
			b.Fatalf("Verify: %v", err)
		}
		ks.Delete(id)
	}
}

func BenchmarkRootKeyStoreGenerate(b *testing.B) {
	ks := NewRootKeyStore()
	expiry := time.Now().Add(30 * time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("bench-key-%d", i)
		_, err := ks.Generate(id, expiry)
		if err != nil {
			b.Fatalf("Generate: %v", err)
		}
		ks.Delete(id)
	}
}

func BenchmarkRootKeyStoreLookup(b *testing.B) {
	ks := NewRootKeyStore()
	expiry := time.Now().Add(30 * time.Minute)

	// Pre-populate with 1000 keys to simulate realistic lookup.
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("lookup-key-%d", i)
		_, _ = ks.Generate(id, expiry)
	}

	// Benchmark lookup of a known key.
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, ok := ks.Get("lookup-key-500")
		if !ok {
			b.Fatal("key not found")
		}
	}
}
