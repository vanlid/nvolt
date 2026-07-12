// Package pinentry resolves a PKCS#11 PIN from the configured pin_mode.
//
// It is deliberately a leaf package (stdlib + golang.org/x/term only) so
// both internal/cli (enrollment via init/join --pkcs11 and `nvolt rebind
// --pkcs11`) and internal/keyprovider (runtime unwrap via resolvePIN) can
// import it without creating an import cycle: internal/cli already imports
// internal/keyprovider, so PIN entry cannot live in internal/cli.
package pinentry

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// Read resolves the PKCS#11 PIN for the given pin_mode:
//   - "prompt": print a prompt to stderr and read the PIN from the TTY
//     without echoing it.
//   - "env": read NVOLT_PKCS11_PIN (error if unset/empty).
//   - "none" or "": no PIN is needed (pinpad / protected authentication
//     path); returns "".
func Read(mode string) (string, error) {
	switch mode {
	case "prompt":
		fmt.Fprint(os.Stderr, "🔑 Enter PKCS#11 PIN: ")
		pin, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read PIN: %w", err)
		}
		return string(pin), nil
	case "env":
		pin := os.Getenv("NVOLT_PKCS11_PIN")
		if pin == "" {
			return "", errors.New("pin_mode=env but NVOLT_PKCS11_PIN is not set")
		}
		return pin, nil
	case "none", "":
		return "", nil
	default:
		return "", fmt.Errorf("unknown pin_mode %q", mode)
	}
}
