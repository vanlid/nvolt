package crypto

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"io"
	"testing"
)

func TestWrapUnwrapKey(t *testing.T) {
	// Generate keypair
	privateKey, err := GenerateRSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	publicKey := &privateKey.PublicKey

	// Generate AES key to wrap
	aesKey, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Wrap the key
	wrappedKey, err := WrapKey(publicKey, aesKey)
	if err != nil {
		t.Fatalf("Failed to wrap key: %v", err)
	}

	if len(wrappedKey) == 0 {
		t.Error("Wrapped key is empty")
	}

	// Unwrap the key
	unwrappedKey, err := UnwrapKey(privateKey, wrappedKey)
	if err != nil {
		t.Fatalf("Failed to unwrap key: %v", err)
	}

	// Verify the unwrapped key matches the original
	if !bytes.Equal(aesKey, unwrappedKey) {
		t.Error("Unwrapped key doesn't match original key")
	}
}

func TestWrapKeyDeterministic(t *testing.T) {
	privateKey, err := GenerateRSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	publicKey := &privateKey.PublicKey

	aesKey, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Wrap the same key twice
	wrappedKey1, err := WrapKey(publicKey, aesKey)
	if err != nil {
		t.Fatalf("Failed to wrap key first time: %v", err)
	}

	wrappedKey2, err := WrapKey(publicKey, aesKey)
	if err != nil {
		t.Fatalf("Failed to wrap key second time: %v", err)
	}

	// Wrapped keys should be different due to random padding in OAEP
	if bytes.Equal(wrappedKey1, wrappedKey2) {
		t.Error("Wrapped keys should be different each time due to random padding")
	}

	// But both should unwrap to the same original key
	unwrapped1, err := UnwrapKey(privateKey, wrappedKey1)
	if err != nil {
		t.Fatalf("Failed to unwrap first key: %v", err)
	}

	unwrapped2, err := UnwrapKey(privateKey, wrappedKey2)
	if err != nil {
		t.Fatalf("Failed to unwrap second key: %v", err)
	}

	if !bytes.Equal(unwrapped1, aesKey) || !bytes.Equal(unwrapped2, aesKey) {
		t.Error("Both unwrapped keys should match the original")
	}
}

func TestUnwrapKeyWrongPrivateKey(t *testing.T) {
	// Generate two keypairs
	privateKey1, err := GenerateRSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate first keypair: %v", err)
	}

	privateKey2, err := GenerateRSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate second keypair: %v", err)
	}

	publicKey1 := &privateKey1.PublicKey

	// Generate and wrap key with first public key
	aesKey, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	wrappedKey, err := WrapKey(publicKey1, aesKey)
	if err != nil {
		t.Fatalf("Failed to wrap key: %v", err)
	}

	// Try to unwrap with wrong private key
	_, err = UnwrapKey(privateKey2, wrappedKey)
	if err == nil {
		t.Error("Expected error when unwrapping with wrong private key")
	}
}

func TestWrapKeyNilPublicKey(t *testing.T) {
	aesKey, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	_, err = WrapKey(nil, aesKey)
	if err == nil {
		t.Error("Expected error when wrapping with nil public key")
	}
}

func TestUnwrapKeyNilPrivateKey(t *testing.T) {
	wrappedKey := []byte("dummy wrapped key")

	_, err := UnwrapKey(nil, wrappedKey)
	if err == nil {
		t.Error("Expected error when unwrapping with nil private key")
	}
}

func TestWrapUnwrapFullWorkflow(t *testing.T) {
	// This test simulates the full workflow:
	// 1. Generate machine keypair
	// 2. Generate project master key
	// 3. Wrap master key for machine
	// 4. Unwrap master key
	// 5. Use master key to encrypt/decrypt data

	// Step 1: Generate machine keypair
	machinePrivateKey, err := GenerateRSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate machine keypair: %v", err)
	}
	machinePublicKey := &machinePrivateKey.PublicKey

	// Step 2: Generate project master key
	masterKey, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	// Step 3: Wrap master key for machine
	wrappedMasterKey, err := WrapKey(machinePublicKey, masterKey)
	if err != nil {
		t.Fatalf("Failed to wrap master key: %v", err)
	}

	// Step 4: Unwrap master key (simulating another session)
	unwrappedMasterKey, err := UnwrapKey(machinePrivateKey, wrappedMasterKey)
	if err != nil {
		t.Fatalf("Failed to unwrap master key: %v", err)
	}

	// Verify master key matches
	if !bytes.Equal(masterKey, unwrappedMasterKey) {
		t.Error("Unwrapped master key doesn't match original")
	}

	// Step 5: Use master key to encrypt/decrypt data
	secretData := []byte("DATABASE_PASSWORD=super_secret_123")

	ciphertext, nonce, err := EncryptAESGCM(unwrappedMasterKey, secretData)
	if err != nil {
		t.Fatalf("Failed to encrypt with unwrapped master key: %v", err)
	}

	decrypted, err := DecryptAESGCM(unwrappedMasterKey, ciphertext, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(secretData, decrypted) {
		t.Error("Decrypted data doesn't match original")
	}
}

func TestWrapKeyTooLarge(t *testing.T) {
	privateKey, err := GenerateRSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	publicKey := &privateKey.PublicKey

	// Try to wrap data that's too large for RSA-OAEP
	// RSA-OAEP can encrypt data up to (key_size - 2*hash_size - 2) bytes
	// For 4096-bit key with SHA256: (512 - 2*32 - 2) = 446 bytes
	largeData := make([]byte, 500)

	_, err = WrapKey(publicKey, largeData)
	if err == nil {
		t.Error("Expected error when wrapping data that's too large")
	}
}

func TestUnwrapKeyAcceptsDecrypter(t *testing.T) {
	key, _ := GenerateRSAKeypair()
	aes, _ := GenerateAESKey()
	wrapped, _ := WrapKey(&key.PublicKey, aes)
	// *rsa.PrivateKey satisfies crypto.Decrypter
	got, err := UnwrapKey(key, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, aes) {
		t.Fatal("mismatch")
	}
}

// fakeDecrypter is a crypto.Decrypter that is NOT *rsa.PrivateKey, used to
// prove UnwrapKey accepts the interface (this would not compile under the
// old *rsa.PrivateKey signature).
type fakeDecrypter struct{ inner *rsa.PrivateKey }

func (f fakeDecrypter) Public() crypto.PublicKey { return f.inner.Public() }
func (f fakeDecrypter) Decrypt(r io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return f.inner.Decrypt(r, msg, opts)
}

func TestUnwrapKeyAcceptsNonRSADecrypter(t *testing.T) {
	key, _ := GenerateRSAKeypair()
	aes, _ := GenerateAESKey()
	wrapped, _ := WrapKey(&key.PublicKey, aes)
	var dec crypto.Decrypter = fakeDecrypter{inner: key} // concrete type is fakeDecrypter, not *rsa.PrivateKey
	got, err := UnwrapKey(dec, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, aes) {
		t.Fatal("mismatch")
	}
}

func BenchmarkWrapKey(b *testing.B) {
	privateKey, err := GenerateRSAKeypair()
	if err != nil {
		b.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	aesKey, err := GenerateAESKey()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := WrapKey(publicKey, aesKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnwrapKey(b *testing.B) {
	privateKey, err := GenerateRSAKeypair()
	if err != nil {
		b.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	aesKey, err := GenerateAESKey()
	if err != nil {
		b.Fatal(err)
	}

	wrappedKey, err := WrapKey(publicKey, aesKey)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := UnwrapKey(privateKey, wrappedKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}
