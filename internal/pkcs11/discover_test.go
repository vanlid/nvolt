package pkcs11

import "testing"

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
		if k.TokenLabel != "nvolt-test" {
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
