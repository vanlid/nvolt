//go:build nvolt_dev && (pkcs11 || tpm_static)

package cli

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/iluxav/nvolt/internal/pinentry"
	"github.com/iluxav/nvolt/internal/pkcs11"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/spf13/cobra"
)

// This file adds two DEV-BUILD-ONLY (build tag nvolt_dev) `nvolt pkcs11`
// subcommands — `delete` and `relabel` — for destructive token maintenance while
// iterating on nvolt itself. They are deliberately absent from released binaries:
// without the nvolt_dev tag this file is not compiled, so cobra simply reports
// "unknown command". It additionally requires a real PKCS#11 loader
// (pkcs11 || tpm_static) because it drives pkcs11.Open/Session directly; the
// Session.DeleteKeyByID / RelabelKeyByID methods it calls live in the loader
// file (session.go) and ship in every such build — only this CLI surface is
// gated.

var (
	pkcs11DelModule  string
	pkcs11DelToken   string
	pkcs11DelID      string
	pkcs11DelPinMode string

	pkcs11RelModule  string
	pkcs11RelToken   string
	pkcs11RelID      string
	pkcs11RelLabel   string
	pkcs11RelPinMode string
)

var pkcs11DeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Destroy the RSA key object(s) with a given CKA_ID (dev builds only)",
	Long: `Destroy both halves (private and public) of the RSA key with the given
CKA_ID on a token, via C_DestroyObject. Logs in first (private objects need the
PIN). Dev-build-only maintenance command.

Example:
  nvolt pkcs11 delete --pkcs11-module /usr/lib/softhsm/libsofthsm2.so \
    --token nvolt-test --id 03`,
	RunE: func(cmd *cobra.Command, args []string) error {
		module, err := pkcs11.ResolveModulePath(pkcs11DelModule)
		if err != nil {
			return err
		}
		return runPKCS11Delete(module, pkcs11DelToken, pkcs11DelID, pkcs11DelPinMode)
	},
}

var pkcs11RelabelCmd = &cobra.Command{
	Use:   "relabel",
	Short: "Set CKA_LABEL on the RSA key object(s) with a given CKA_ID (dev builds only)",
	Long: `Set CKA_LABEL to a new value on both halves (private and public) of the
RSA key with the given CKA_ID on a token, via C_SetAttributeValue. Logs in first.
Dev-build-only maintenance command.

Example:
  nvolt pkcs11 relabel --pkcs11-module /usr/lib/softhsm/libsofthsm2.so \
    --token nvolt-test --id 03 --label renamed-key`,
	RunE: func(cmd *cobra.Command, args []string) error {
		module, err := pkcs11.ResolveModulePath(pkcs11RelModule)
		if err != nil {
			return err
		}
		return runPKCS11Relabel(module, pkcs11RelToken, pkcs11RelID, pkcs11RelLabel, pkcs11RelPinMode)
	},
}

// runPKCS11Delete opens a logged-in RW session on the named token and destroys
// both halves of the key with CKA_ID idHex.
func runPKCS11Delete(module, token, idHex, pinMode string) error {
	id, err := decodeKeyID(idHex)
	if err != nil {
		return err
	}
	sess, closeFn, err := openLoginRWSession(module, token, pinMode)
	if err != nil {
		return err
	}
	defer closeFn()

	n, err := sess.DeleteKeyByID(id)
	if err != nil {
		return fmt.Errorf("failed to delete key id %s: %w", idHex, err)
	}
	if n == 0 {
		// ui.Warning is single-pass Printf, so the raw token is a safe %s argument.
		ui.Warning("No key object with id %s found on token %s", idHex, token)
		return nil
	}
	// ui.Success double-formats (Sprintf then Info re-parses), so escape "%" in
	// the user-controlled token; idHex is hex-only and n an int, both safe.
	ui.Success("Destroyed %d object(s) with id %s on token %s",
		n, idHex, strings.ReplaceAll(token, "%", "%%"))
	return nil
}

// runPKCS11Relabel opens a logged-in RW session on the named token and sets
// CKA_LABEL to label on both halves of the key with CKA_ID idHex.
func runPKCS11Relabel(module, token, idHex, label, pinMode string) error {
	if label == "" {
		return fmt.Errorf("--label is required")
	}
	id, err := decodeKeyID(idHex)
	if err != nil {
		return err
	}
	sess, closeFn, err := openLoginRWSession(module, token, pinMode)
	if err != nil {
		return err
	}
	defer closeFn()

	n, err := sess.RelabelKeyByID(id, label)
	if err != nil {
		return fmt.Errorf("failed to relabel key id %s: %w", idHex, err)
	}
	if n == 0 {
		ui.Warning("No key object with id %s found on token %s", idHex, token)
		return nil
	}
	// ui.Success double-formats: escape "%" in the user-controlled token/label.
	ui.Success("Relabeled %d object(s) with id %s to %s on token %s",
		n, idHex, strings.ReplaceAll(label, "%", "%%"), strings.ReplaceAll(token, "%", "%%"))
	return nil
}

// decodeKeyID parses a required, non-empty hex CKA_ID (e.g. "03").
func decodeKeyID(idHex string) ([]byte, error) {
	id, err := hex.DecodeString(idHex)
	if err != nil {
		return nil, fmt.Errorf("invalid --id hex %q: %w", idHex, err)
	}
	if len(id) == 0 {
		return nil, fmt.Errorf("--id is required (hex, e.g. 03)")
	}
	return id, nil
}

// openLoginRWSession opens module, reads the PIN per pinMode, opens a RW session
// on token, and logs in (an empty PIN skips C_Login, the pin_mode=none path). It
// returns the session and a close function that closes both the session and the
// module. Unlike generate/import it does not auto-initialize a blank token:
// delete/relabel operate on a token that already holds the target key.
func openLoginRWSession(module, token, pinMode string) (*pkcs11.Session, func(), error) {
	if token == "" {
		return nil, nil, fmt.Errorf("no PKCS#11 token specified; use --token")
	}
	m, err := pkcs11.Open(module)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open PKCS#11 module: %w", err)
	}
	pin, err := pinentry.Read(pinMode)
	if err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("failed to obtain PIN: %w", err)
	}
	sess, err := m.OpenSessionRW(token)
	if err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("failed to open session on token %q: %w", token, err)
	}
	if pin != "" {
		if err := sess.Login(pin); err != nil {
			_ = sess.Close()
			_ = m.Close()
			return nil, nil, fmt.Errorf("failed to log in: %w", err)
		}
	}
	return sess, func() { _ = sess.Close(); _ = m.Close() }, nil
}

func init() {
	pkcs11DeleteCmd.Flags().StringVar(&pkcs11DelModule, "pkcs11-module", "", "Path to PKCS#11 module (.so); autodetected if omitted")
	pkcs11DeleteCmd.Flags().StringVar(&pkcs11DelToken, "token", "", "Token label the key lives on (required)")
	pkcs11DeleteCmd.Flags().StringVar(&pkcs11DelID, "id", "", "CKA_ID of the key to destroy, hex (e.g. 03) (required)")
	pkcs11DeleteCmd.Flags().StringVar(&pkcs11DelPinMode, "pkcs11-pin-mode", "prompt", "How to obtain the PIN: prompt, env, or none")
	_ = pkcs11DeleteCmd.MarkFlagRequired("token")
	_ = pkcs11DeleteCmd.MarkFlagRequired("id")
	pkcs11Cmd.AddCommand(pkcs11DeleteCmd)

	pkcs11RelabelCmd.Flags().StringVar(&pkcs11RelModule, "pkcs11-module", "", "Path to PKCS#11 module (.so); autodetected if omitted")
	pkcs11RelabelCmd.Flags().StringVar(&pkcs11RelToken, "token", "", "Token label the key lives on (required)")
	pkcs11RelabelCmd.Flags().StringVar(&pkcs11RelID, "id", "", "CKA_ID of the key to relabel, hex (e.g. 03) (required)")
	pkcs11RelabelCmd.Flags().StringVar(&pkcs11RelLabel, "label", "", "New CKA_LABEL for the key (required)")
	pkcs11RelabelCmd.Flags().StringVar(&pkcs11RelPinMode, "pkcs11-pin-mode", "prompt", "How to obtain the PIN: prompt, env, or none")
	_ = pkcs11RelabelCmd.MarkFlagRequired("token")
	_ = pkcs11RelabelCmd.MarkFlagRequired("id")
	_ = pkcs11RelabelCmd.MarkFlagRequired("label")
	pkcs11Cmd.AddCommand(pkcs11RelabelCmd)
}
