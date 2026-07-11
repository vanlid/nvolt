package cli

import "testing"

// TestDecidePKCS11InitAction pins down init/join's idempotency policy for the
// --pkcs11 path: reuse an existing hardware identity, refuse to silently
// replace a software one, and enroll when the machine has no identity yet.
func TestDecidePKCS11InitAction(t *testing.T) {
	cases := []struct {
		name        string
		initialized bool
		source      string
		want        pkcs11InitAction
	}{
		{"fresh enrolls", false, "", pkcs11ActionEnroll},
		{"existing pkcs11 is reused", true, "pkcs11", pkcs11ActionReuse},
		{"existing software conflicts", true, "software", pkcs11ActionSoftwareConflict},
		{"existing unknown source conflicts", true, "", pkcs11ActionSoftwareConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := decidePKCS11InitAction(c.initialized, c.source); got != c.want {
				t.Errorf("decidePKCS11InitAction(%v, %q) = %d, want %d",
					c.initialized, c.source, got, c.want)
			}
		})
	}
}
