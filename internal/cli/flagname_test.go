package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestSharedPKCS11FlagsArePrefixed(t *testing.T) {
	// init & join expose the prefixed shared flags, not the bare ones.
	for _, c := range []*cobra.Command{initCmd, joinCmd} {
		names := map[string]bool{}
		c.Flags().VisitAll(func(f *pflag.Flag) { names[f.Name] = true })
		for _, want := range []string{"pkcs11", "pkcs11-module", "pkcs11-uri", "pkcs11-pin-mode"} {
			if !names[want] {
				t.Errorf("%s missing --%s", c.Name(), want)
			}
		}
		for _, bare := range []string{"module", "uri", "pin-mode"} {
			if names[bare] {
				t.Errorf("%s still has bare --%s", c.Name(), bare)
			}
		}
	}
}
