package cli

import (
	"crypto/rsa"
	"fmt"
	"os"

	nvcrypto "github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/keyprovider"
	"github.com/iluxav/nvolt/internal/pinentry"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/iluxav/nvolt/pkg/types"
	"github.com/spf13/cobra"
)

var rebindPKCS11, rebindSoftware bool
var rebindModule, rebindURI, rebindPinMode, rebindPrivkey string

var rebindCmd = &cobra.Command{
	Use:   "rebind",
	Short: "Re-point this machine's identity between software and hardware backing (same key)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRebind()
	},
}

func samePublicKey(a, b *rsa.PublicKey) bool {
	return a != nil && b != nil && a.N.Cmp(b.N) == 0 && a.E == b.E
}

func runRebind() error {
	if rebindPKCS11 == rebindSoftware { // both or neither
		return fmt.Errorf("specify exactly one of --pkcs11 or --software")
	}
	if rebindPrivkey != "" && !rebindSoftware {
		return fmt.Errorf("--privkey is only valid with --software")
	}
	mi, err := vault.LoadMachineInfo()
	if err != nil {
		return fmt.Errorf("no machine identity yet; use 'nvolt init --pkcs11' or 'nvolt join --pkcs11': %w", err)
	}
	identityPub, err := nvcrypto.DecodePublicKeyPEM([]byte(mi.PublicKey))
	if err != nil {
		return fmt.Errorf("parse current identity public key: %w", err)
	}
	homePaths, err := vault.GetHomePaths()
	if err != nil {
		return err
	}

	if rebindPKCS11 {
		return rebindToHardware(mi, identityPub, homePaths)
	}
	return rebindToSoftware(mi, identityPub, homePaths)
}

func rebindToHardware(mi *types.MachineInfo, identityPub *rsa.PublicKey, homePaths *vault.HomePaths) error {
	module, uri, err := resolveEnrollTarget(rebindModule, rebindURI)
	if err != nil {
		return err
	}
	// Enroll runs the on-card self-test (proves the card can decrypt) and returns
	// the card's public key + KeySource.
	src, cardPub, err := keyprovider.Enroll(module, uri, rebindPinMode, func() (string, error) {
		return pinentry.Read(rebindPinMode)
	})
	if err != nil {
		return err
	}
	if !samePublicKey(cardPub, identityPub) {
		return fmt.Errorf("the token's public key doesn't match this machine's identity; " +
			"rebind only relocates the same key. To change to a different key, register it " +
			"with 'nvolt machine add' and re-grant")
	}
	mi.KeySource = &src
	if err := vault.SaveMachineInfo(homePaths.MachineInfo, mi); err != nil {
		return err
	}
	ui.Success("%s now backed by hardware (PKCS#11)", mi.ID)
	if vault.FileExists(homePaths.PrivateKey) {
		ui.Info("Your software private key is still at %s and can still decrypt your secrets.", homePaths.PrivateKey)
		ui.Info("Remove it once you've confirmed the card works: rm %s", homePaths.PrivateKey)
	}
	return nil
}

func rebindToSoftware(mi *types.MachineInfo, identityPub *rsa.PublicKey, homePaths *vault.HomePaths) error {
	// Ensure a matching software key is at the forced location.
	if rebindPrivkey != "" {
		data, err := os.ReadFile(rebindPrivkey)
		if err != nil {
			return fmt.Errorf("read %s: %w", rebindPrivkey, err)
		}
		priv, err := nvcrypto.DecodePrivateKeyPEM(data)
		if err != nil {
			return fmt.Errorf("parse private key: %w", err)
		}
		if !samePublicKey(&priv.PublicKey, identityPub) {
			return fmt.Errorf("that key's public key doesn't match this machine's identity")
		}
		if vault.FileExists(homePaths.PrivateKey) {
			existing, _ := os.ReadFile(homePaths.PrivateKey)
			ep, err := nvcrypto.DecodePrivateKeyPEM(existing)
			if err != nil || !samePublicKey(&ep.PublicKey, identityPub) {
				return fmt.Errorf("a different private key already exists at %s — remove or relocate it first", homePaths.PrivateKey)
			}
			// existing already matches: nothing to write.
		} else {
			pemBytes, _ := nvcrypto.EncodePrivateKeyPEM(priv)
			if err := vault.WriteFileAtomic(homePaths.PrivateKey, pemBytes, vault.PrivateKeyPerm); err != nil {
				return err
			}
		}
	} else {
		if !vault.FileExists(homePaths.PrivateKey) {
			return fmt.Errorf("no software key at %s; supply --privkey <path>", homePaths.PrivateKey)
		}
		existing, _ := os.ReadFile(homePaths.PrivateKey)
		ep, err := nvcrypto.DecodePrivateKeyPEM(existing)
		if err != nil || !samePublicKey(&ep.PublicKey, identityPub) {
			return fmt.Errorf("the key at %s doesn't match this machine's identity", homePaths.PrivateKey)
		}
	}
	mi.KeySource = &types.KeySource{Source: "software"}
	if err := vault.SaveMachineInfo(homePaths.MachineInfo, mi); err != nil {
		return err
	}
	ui.Success("%s now backed by software", mi.ID)
	return nil
}

func init() {
	rebindCmd.Flags().BoolVar(&rebindPKCS11, "pkcs11", false, "Re-point to a PKCS#11 token (sw->hw)")
	rebindCmd.Flags().BoolVar(&rebindSoftware, "software", false, "Re-point to a software key file (hw->sw)")
	rebindCmd.Flags().StringVar(&rebindModule, "pkcs11-module", "", "Path to PKCS#11 module (.so) (with --pkcs11)")
	rebindCmd.Flags().StringVar(&rebindURI, "pkcs11-uri", "", "PKCS#11 URI of the key (with --pkcs11)")
	rebindCmd.Flags().StringVar(&rebindPinMode, "pkcs11-pin-mode", "prompt", "How to obtain the PIN (with --pkcs11)")
	rebindCmd.Flags().StringVar(&rebindPrivkey, "privkey", "", "Private-key PEM to install (with --software)")
	rootCmd.AddCommand(rebindCmd)
}
