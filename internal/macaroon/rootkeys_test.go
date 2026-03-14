package macaroon

import (
	"sync"
	"testing"
	"time"
)

func TestRootKeyStore_GenerateAndGet(t *testing.T) {
	s := NewRootKeyStore()
	expiry := time.Now().Add(time.Hour)

	key, err := s.Generate("task-001", expiry)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Key should be non-zero.
	var zero [32]byte
	if key == zero {
		t.Fatal("generated key is all zeros")
	}

	// Get should return the same key.
	got, ok := s.Get("task-001")
	if !ok {
		t.Fatal("Get returned false for existing key")
	}
	if got != key {
		t.Fatalf("Get returned different key:\n  got  %x\n  want %x", got, key)
	}
}

func TestRootKeyStore_GetNotFound(t *testing.T) {
	s := NewRootKeyStore()

	_, ok := s.Get("nonexistent-task")
	if ok {
		t.Fatal("Get returned true for nonexistent key")
	}
}

func TestRootKeyStore_Delete(t *testing.T) {
	s := NewRootKeyStore()
	expiry := time.Now().Add(time.Hour)

	_, err := s.Generate("task-del", expiry)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Should exist.
	if _, ok := s.Get("task-del"); !ok {
		t.Fatal("key should exist before delete")
	}

	// Delete it.
	s.Delete("task-del")

	// Should no longer exist.
	if _, ok := s.Get("task-del"); ok {
		t.Fatal("key should not exist after delete")
	}
}

func TestRootKeyStore_ExtendMaxExpiry(t *testing.T) {
	s := NewRootKeyStore()
	initial := time.Now().Add(time.Hour)

	_, err := s.Generate("task-ext", initial)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Extend to a later time.
	later := initial.Add(2 * time.Hour)
	s.ExtendMaxExpiry("task-ext", later)

	// Key should still be retrievable.
	if _, ok := s.Get("task-ext"); !ok {
		t.Fatal("key should exist after extend")
	}

	// Try to "extend" to an earlier time — should not shorten.
	earlier := initial.Add(-time.Hour)
	s.ExtendMaxExpiry("task-ext", earlier)

	// The key should survive cleanup until "later" passes.
	// We can't directly inspect maxExpiry, but we can verify via Cleanup behavior:
	// Set time far enough that only the "later" expiry would keep it alive.
	// Since we can't mock time, we just verify the key still exists.
	if _, ok := s.Get("task-ext"); !ok {
		t.Fatal("key should still exist after no-op extend")
	}

	// ExtendMaxExpiry on nonexistent key should be a no-op.
	s.ExtendMaxExpiry("nonexistent", later)
}

func TestRootKeyStore_Cleanup(t *testing.T) {
	s := NewRootKeyStore()

	// Create a key that expires in the past.
	past := time.Now().Add(-time.Hour)
	_, err := s.Generate("task-expired", past)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Create a key that expires in the future.
	future := time.Now().Add(time.Hour)
	_, err = s.Generate("task-alive", future)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if s.Count() != 2 {
		t.Fatalf("count before cleanup = %d, want 2", s.Count())
	}

	// Cleanup should remove the expired key.
	s.Cleanup()

	if s.Count() != 1 {
		t.Fatalf("count after cleanup = %d, want 1", s.Count())
	}

	// Expired key should be gone.
	if _, ok := s.Get("task-expired"); ok {
		t.Fatal("expired key should be removed after cleanup")
	}

	// Alive key should remain.
	if _, ok := s.Get("task-alive"); !ok {
		t.Fatal("alive key should survive cleanup")
	}
}

func TestRootKeyStore_Count(t *testing.T) {
	s := NewRootKeyStore()
	expiry := time.Now().Add(time.Hour)

	if s.Count() != 0 {
		t.Fatalf("initial count = %d, want 0", s.Count())
	}

	for i := 0; i < 5; i++ {
		_, err := s.Generate("task-"+string(rune('A'+i)), expiry)
		if err != nil {
			t.Fatalf("Generate %d: %v", i, err)
		}
	}

	if s.Count() != 5 {
		t.Fatalf("count after 5 generates = %d, want 5", s.Count())
	}

	s.Delete("task-A")
	if s.Count() != 4 {
		t.Fatalf("count after delete = %d, want 4", s.Count())
	}
}

func TestRootKeyStore_ConcurrentAccess(t *testing.T) {
	s := NewRootKeyStore()
	expiry := time.Now().Add(time.Hour)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()

			id := "task-" + string(rune('A'+n%26)) + string(rune('0'+n/26))

			// Generate.
			_, _ = s.Generate(id, expiry)

			// Get.
			s.Get(id)

			// ExtendMaxExpiry.
			s.ExtendMaxExpiry(id, expiry.Add(time.Duration(n)*time.Minute))

			// Count.
			s.Count()

			// Cleanup (safe to call concurrently).
			if n%10 == 0 {
				s.Cleanup()
			}

			// Delete some.
			if n%7 == 0 {
				s.Delete(id)
			}
		}(i)
	}

	wg.Wait()

	// If we get here without a race detector panic, the test passes.
	// Just verify count is non-negative.
	if s.Count() < 0 {
		t.Fatal("count should be non-negative")
	}
}
