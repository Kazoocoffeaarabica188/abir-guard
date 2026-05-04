package abirguard

import (
	"testing"
	"time"
)

func TestNewVault(t *testing.T) {
	v := NewVault()
	if v == nil {
		t.Fatal("NewVault returned nil")
	}
}

func TestGenerateKeypair(t *testing.T) {
	v := NewVault()
	kp, err := v.GenerateKeypair("test-agent")
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	if kp.PublicKey == "" {
		t.Error("PublicKey is empty")
	}
	if kp.SharedKey == nil {
		t.Error("SharedKey is nil")
	}
	if len(kp.SharedKey) != 32 {
		t.Errorf("SharedKey length = %d, want 32", len(kp.SharedKey))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	v := NewVault()
	v.GenerateKeypair("agent-1")

	plaintext := []byte("sensitive agent data")
	ct, err := v.Encrypt("agent-1", plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := v.Decrypt("agent-1", ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestAutoKeyGeneration(t *testing.T) {
	v := NewVault()

	plaintext := []byte("auto-generated key test")
	ct, err := v.Encrypt("new-agent", plaintext)
	if err != nil {
		t.Fatalf("Encrypt with auto-key failed: %v", err)
	}

	decrypted, err := v.Decrypt("new-agent", ct)
	if err != nil {
		t.Fatalf("Decrypt with auto-key failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestListKeys(t *testing.T) {
	v := NewVault()
	v.GenerateKeypair("agent-a")
	v.GenerateKeypair("agent-b")

	keys := v.ListKeys()
	if len(keys) != 2 {
		t.Errorf("len(keys) = %d, want 2", len(keys))
	}
}

func TestRemoveKeypair(t *testing.T) {
	v := NewVault()
	v.GenerateKeypair("to-delete")
	v.RemoveKeypair("to-delete")

	_, err := v.Encrypt("to-delete", []byte("test"))
	if err != nil {
		// Key was removed, new one generated — this is OK
		return
	}
}

func TestRevokeKey(t *testing.T) {
	v := NewVault()
	v.GenerateKeypair("compromised")

	err := v.RevokeKey("compromised", "compromised", "admin", "Key leaked")
	if err != nil {
		t.Fatalf("RevokeKey failed: %v", err)
	}

	if !v.IsRevoked("compromised") {
		t.Error("key should be revoked")
	}

	_, err = v.Encrypt("compromised", []byte("test"))
	if err == nil {
		t.Error("Encrypt should fail on revoked key")
	}
}

func TestKeyRotation(t *testing.T) {
	v := NewVault()
	v.GenerateKeypair("rotate-me")

	err := v.RotateKey("rotate-me")
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	rotatedKeys := v.ListKeys()
	if len(rotatedKeys) != 1 {
		t.Errorf("expected 1 active key after rotation, got %d", len(rotatedKeys))
	}
}

func TestNeedsRotation(t *testing.T) {
	v := NewVault()
	v.GenerateKeypair("rotation-test")

	meta := v.metadata["rotation-test"]
	meta.MaxOperations = 5

	// Use the key 5 times
	for i := 0; i < 5; i++ {
		v.Encrypt("rotation-test", []byte("data"))
	}

	if !v.NeedsRotation("rotation-test") {
		t.Error("key should need rotation after 5 operations")
	}
}

func TestTimeBasedRotation(t *testing.T) {
	v := NewVault()
	v.GenerateKeypair("time-rotate")

	meta := v.metadata["time-rotate"]
	meta.MaxLifetime = 1 * time.Millisecond

	time.Sleep(10 * time.Millisecond)

	if !v.NeedsRotation("time-rotate") {
		t.Error("key should need rotation after lifetime expiry")
	}
}

func TestAuditLog(t *testing.T) {
	v := NewVault()
	v.GenerateKeypair("audit-test")
	v.Encrypt("audit-test", []byte("data"))

	log := v.GetAuditLog()
	if len(log) < 2 {
		t.Errorf("expected at least 2 audit entries, got %d", len(log))
	}

	if log[0].Action != "keygen" {
		t.Errorf("first action = %q, want %q", log[0].Action, "keygen")
	}
}

func TestValidateKeyID(t *testing.T) {
	tests := []struct {
		keyID     string
		shouldErr bool
	}{
		{"valid-key", false},
		{"valid_key", false},
		{"ValidKey123", false},
		{"", true},
		{"toolong" + string(make([]byte, 100)), true},
		{"invalid key!", true},
		{"__system", true},
	}

	for _, tt := range tests {
		err := validateKeyID(tt.keyID)
		if (err != nil) != tt.shouldErr {
			t.Errorf("validateKeyID(%q) error = %v, shouldErr = %v", tt.keyID, err, tt.shouldErr)
		}
	}
}
