//go:build pkcs11

package pkcs11

import "testing"

// testTokenLabel is the SoftHSM fixture token label used by this file's tests.
const testTokenLabel = "nvolt-test"

// TestListRSAKeys enumerates the SoftHSM fixture token and asserts the
// nvolt-test / id=01 RSA key is discovered with its bit size and label.
func TestListRSAKeys(t *testing.T) {
	keys, err := ListRSAKeys(testModulePath(t))
	if err != nil {
		t.Fatalf("ListRSAKeys: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("expected at least one RSA key")
	}

	var found bool
	for _, k := range keys {
		if k.TokenLabel != testTokenLabel {
			continue
		}
		if len(k.ID) == 1 && k.ID[0] == 0x01 {
			if k.Bits < 2048 {
				t.Fatalf("id=01 key has %d bits, want >= 2048", k.Bits)
			}
			if k.Label == "" {
				t.Fatal("id=01 key has empty label")
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("nvolt-test/id=01 key not found in %+v", keys)
	}
}

// TestListTokensAndKeysIncludesToken enumerates the SoftHSM fixture token via
// ListTokensAndKeys (the per-token API ListRSAKeys is now built on) and
// asserts the fixture token is represented, with its RSA keys attached.
func TestListTokensAndKeysIncludesToken(t *testing.T) {
	tokens, err := ListTokensAndKeys(testModulePath(t))
	if err != nil {
		t.Fatalf("ListTokensAndKeys: %v", err)
	}
	if len(tokens) == 0 {
		t.Fatal("expected at least one token")
	}

	var found *TokenListing
	for i := range tokens {
		if tokens[i].Label == testTokenLabel {
			found = &tokens[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("nvolt-test token not found in %+v", tokens)
	}
	if len(found.Keys) == 0 {
		t.Fatalf("expected nvolt-test token to have RSA keys, got none: %+v", *found)
	}
}
