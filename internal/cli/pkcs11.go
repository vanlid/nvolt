package cli

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	nvcrypto "github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/keyprovider"
	"github.com/iluxav/nvolt/internal/pinentry"
	"github.com/iluxav/nvolt/internal/pkcs11"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/iluxav/nvolt/pkg/types"
	"github.com/spf13/cobra"
)

var pkcs11Module string
var pkcs11UseModule string
var pkcs11UseURI string
var pkcs11UsePinMode string
var pkcs11UseForce bool

var pkcs11GenModule string
var pkcs11GenToken string
var pkcs11GenLabel string
var pkcs11GenID string
var pkcs11GenBits int
var pkcs11GenPinMode string

var pkcs11Cmd = &cobra.Command{
	Use:   "pkcs11",
	Short: "Interact with PKCS#11 hardware tokens (YubiKey, SoftHSM, etc.)",
	Long: `Discover and use RSA keys stored on PKCS#11 tokens such as a YubiKey
or SoftHSM, via a PKCS#11 module (.so).`,
}

var pkcs11ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List RSA keys visible on a PKCS#11 token",
	Long: `Enumerate tokens and RSA keys visible through a PKCS#11 module.

Discovery does not log in, so it reports whatever RSA key objects the token
exposes without a PIN.

Example:
  nvolt pkcs11 list --module /usr/lib/softhsm/libsofthsm2.so`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// An explicit --module or NVOLT_PKCS11_MODULE targets a single module.
		// Otherwise, autodiscover and list every module we find.
		if pkcs11Module != "" || os.Getenv("NVOLT_PKCS11_MODULE") != "" {
			module, err := pkcs11.ResolveModulePath(pkcs11Module)
			if err != nil {
				return err
			}
			return runPKCS11List(module)
		}
		return runPKCS11ListDiscovered()
	},
}

// runPKCS11ListDiscovered enumerates PKCS#11 modules via pkcs11.DetectModules
// and lists each one's tokens/keys under a header. A module that fails to open
// or list (e.g. a p11-kit-client with no server) yields a warning and the scan
// continues, so one bad provider never aborts the whole listing.
func runPKCS11ListDiscovered() error {
	mods := pkcs11.DetectModules()
	if len(mods) == 0 {
		ui.Warning("No PKCS#11 modules found (looked in common install locations); pass --module <path> or set NVOLT_PKCS11_MODULE")
		return nil
	}

	for _, m := range mods {
		// Section prints its argument via %s (no re-parse), but Path/Source go
		// through PrintKeyValue -> Info which double-formats, so escape "%".
		ui.Section(m.Label)
		ui.PrintKeyValue("  Path", strings.ReplaceAll(m.Path, "%", "%%"))
		ui.PrintKeyValue("  Source", m.Source)
		if err := runPKCS11List(m.Path); err != nil {
			ui.Warning("  Skipping %s: %s",
				strings.ReplaceAll(m.Path, "%", "%%"),
				strings.ReplaceAll(err.Error(), "%", "%%"))
		}
	}

	return nil
}

func runPKCS11List(module string) error {
	keys, err := pkcs11.ListRSAKeys(module)
	if err != nil {
		return fmt.Errorf("failed to list PKCS#11 keys: %w", err)
	}

	if len(keys) == 0 {
		ui.Warning("No RSA keys found on module %s", module)
		return nil
	}

	ui.Section(fmt.Sprintf("RSA keys (%d):", len(keys)))
	for _, k := range keys {
		// ui.PrintKeyValue -> ui.Info double-formats (see enrollPKCS11Machine/
		// runPKCS11Generate below): any "%" in card-derived token/key labels
		// gets reinterpreted as a format verb on the second pass. Escape
		// "%" -> "%%" for consistency with those sibling commands.
		ui.PrintKeyValue("  Token", ui.Cyan(strings.ReplaceAll(k.TokenLabel, "%", "%%")))
		ui.PrintKeyValue("  Label", strings.ReplaceAll(k.Label, "%", "%%"))
		ui.PrintKeyValue("  ID", fmt.Sprintf("%x", k.ID))
		ui.PrintKeyValue("  Bits", fmt.Sprintf("%d", k.Bits))
		fmt.Println()
	}

	return nil
}

var pkcs11UseCmd = &cobra.Command{
	Use:   "use",
	Short: "Enroll an on-card RSA key as this machine's identity",
	Long: `Enroll an RSA key stored on a PKCS#11 token (YubiKey, SoftHSM, etc.)
as this machine's identity, replacing the usual software keypair.

nvolt validates the token key (RSA >= 2048 bits, OAEP-SHA256 unwrap support)
before persisting anything, then records the module/URI/PIN-mode/OAEP-mode
in machine-info.json so pull/push know how to reach the key at runtime.

Example:
  nvolt pkcs11 use --module /usr/lib/softhsm/libsofthsm2.so \
    --uri 'pkcs11:token=nvolt-test;id=%01;type=private' --pin-mode prompt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		module, err := pkcs11.ResolveModulePath(pkcs11UseModule)
		if err != nil {
			return err
		}
		return runPKCS11Use(module, pkcs11UseURI, pkcs11UsePinMode, pkcs11UseForce)
	},
}

// runPKCS11Use is the `nvolt pkcs11 use` command body; it delegates to the
// shared enrollPKCS11Machine so init/join --pkcs11 run the identical flow.
func runPKCS11Use(module, uri, pinMode string, force bool) error {
	return enrollPKCS11Machine(module, uri, pinMode, force)
}

// enrollPKCS11Machine enrolls the on-card key at uri (via module) as this
// machine's identity, mirroring vault.InitializeMachine's machine-info
// construction but sourcing the keypair from the token instead of generating a
// software one. It is the single enroll implementation shared by
// `nvolt pkcs11 use` and the --pkcs11 branch of init/join.
func enrollPKCS11Machine(module, uri, pinMode string, force bool) error {
	if module == "" {
		return fmt.Errorf("no PKCS#11 module specified; use --module or set NVOLT_PKCS11_MODULE")
	}
	if uri == "" {
		return fmt.Errorf("no PKCS#11 URI specified; use --uri")
	}

	homePaths, err := vault.GetHomePaths()
	if err != nil {
		return err
	}

	// Guard against clobbering an existing machine identity, mirroring
	// InitializeMachine's own guard.
	if !force && vault.FileExists(homePaths.MachineInfo) {
		return fmt.Errorf("machine already initialized: %s exists (use --force)", homePaths.MachineInfo)
	}

	src, pub, err := keyprovider.Enroll(module, uri, pinMode, func() (string, error) {
		return pinentry.Read(pinMode)
	})
	if err != nil {
		return fmt.Errorf("failed to enroll PKCS#11 key: %w", err)
	}

	if err := vault.InitializeHomeDirectory(); err != nil {
		return fmt.Errorf("failed to initialize home directory: %w", err)
	}

	publicKeyPEM, err := nvcrypto.EncodePublicKeyPEM(pub)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	fingerprint, err := nvcrypto.GenerateFingerprint(pub)
	if err != nil {
		return fmt.Errorf("failed to generate fingerprint: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	machineInfo := &types.MachineInfo{
		ID:          vault.GenerateMachineID("", hostname, fingerprint),
		PublicKey:   string(publicKeyPEM),
		Fingerprint: fingerprint,
		Hostname:    hostname,
		Description: fmt.Sprintf("Machine: %s", hostname),
		CreatedAt:   time.Now(),
		KeySource:   &src,
	}

	if err := vault.SaveMachineInfo(homePaths.MachineInfo, machineInfo); err != nil {
		return fmt.Errorf("failed to save machine info: %w", err)
	}

	// Moving to a PKCS#11-backed identity (including --force re-enrollment
	// over a machine that previously held a software keypair) must not leave
	// the old software private key on disk: a lingering plaintext key would
	// undermine the point of moving identity to hardware.
	if vault.FileExists(homePaths.PrivateKey) {
		if err := vault.SecureDeleteFile(homePaths.PrivateKey); err != nil {
			return fmt.Errorf("failed to remove orphaned software private key: %w", err)
		}
		ui.Info("Removed orphaned software private key %s (identity now backed by PKCS#11)", homePaths.PrivateKey)
	}

	ui.Section("PKCS#11 machine identity enrolled")
	ui.PrintKeyValue("  Machine ID", machineInfo.ID)
	ui.PrintKeyValue("  Fingerprint", machineInfo.Fingerprint)
	ui.PrintKeyValue("  Module", strings.ReplaceAll(module, "%", "%%"))
	// ui.PrintKeyValue -> ui.Info double-formats: PrintKeyValue's own Sprintf
	// embeds uri literally, but Info's Fprintf(format+"\n", args...) then
	// re-parses that combined string as a format string with zero args. Any
	// "%" byte in uri (e.g. RFC7512 percent-encoded ids like "%01", present
	// in virtually every real pkcs11 URI) gets reinterpreted as a format
	// verb, corrupting the banner (e.g. "id=%!;(MISSING)..."). Escaping
	// "%" -> "%%" here makes it survive that second pass as a literal "%".
	// Not touching shared ui.PrintKeyValue/Info: other call sites depend on
	// their current single-argument passthrough behavior.
	ui.PrintKeyValue("  URI", strings.ReplaceAll(uri, "%", "%%"))
	ui.PrintKeyValue("  OAEP mode", src.OAEPMode)
	ui.Success("Machine %s is now backed by the on-card key", machineInfo.ID)

	return nil
}

var pkcs11GenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate an RSA keypair on a PKCS#11 token",
	Long: `Generate an RSA keypair directly on a PKCS#11 token (SoftHSM, and
tokens that expose C_GenerateKeyPair). The private key never leaves the device.

Example:
  nvolt pkcs11 generate --module /usr/lib/softhsm/libsofthsm2.so \
    --token nvolt-test --label my-key --id 03 --bits 2048`,
	RunE: func(cmd *cobra.Command, args []string) error {
		module, err := pkcs11.ResolveModulePath(pkcs11GenModule)
		if err != nil {
			return err
		}
		return runPKCS11Generate(module, pkcs11GenToken, pkcs11GenLabel, pkcs11GenID, pkcs11GenBits, pkcs11GenPinMode)
	},
}

// runPKCS11Generate opens a session on the named token, logs in, and generates
// an RSA keypair on-card via C_GenerateKeyPair.
func runPKCS11Generate(module, token, label, idHex string, bits int, pinMode string) error {
	if token == "" {
		return fmt.Errorf("no PKCS#11 token specified; use --token")
	}
	if label == "" {
		return fmt.Errorf("no key label specified; use --label")
	}
	id, err := hex.DecodeString(idHex)
	if err != nil {
		return fmt.Errorf("invalid --id (must be hex, e.g. 03): %w", err)
	}
	if len(id) == 0 {
		return fmt.Errorf("no key id specified; use --id (hex, e.g. 03)")
	}
	if bits < 2048 {
		return fmt.Errorf("--bits must be at least 2048 (got %d)", bits)
	}

	m, err := pkcs11.Open(module)
	if err != nil {
		return fmt.Errorf("failed to open PKCS#11 module: %w", err)
	}
	defer m.Close()

	sess, err := m.OpenSessionRW(token)
	if err != nil {
		return fmt.Errorf("failed to open session on token %q: %w", token, err)
	}
	defer sess.Close()

	pin, err := pinentry.Read(pinMode)
	if err != nil {
		return fmt.Errorf("failed to obtain PIN: %w", err)
	}
	if pin != "" {
		if err := sess.Login(pin); err != nil {
			return fmt.Errorf("failed to log in: %w", err)
		}
	}

	if _, err := sess.GenerateRSAKeyPair(label, id, bits); err != nil {
		return fmt.Errorf("failed to generate RSA keypair: %w", err)
	}

	// ui.PrintKeyValue -> ui.Info double-formats (see runPKCS11Use above): any
	// "%" in user-supplied token/label gets reinterpreted as a format verb on
	// the second pass. Escape "%" -> "%%" on the user-controlled strings
	// before display; the hex id is already %-safe but escaping it too is
	// harmless. Numeric bits need no escaping.
	ui.Section("On-card RSA keypair generated")
	ui.PrintKeyValue("  Token", ui.Cyan(strings.ReplaceAll(token, "%", "%%")))
	ui.PrintKeyValue("  Label", strings.ReplaceAll(label, "%", "%%"))
	ui.PrintKeyValue("  ID", strings.ReplaceAll(fmt.Sprintf("%x", id), "%", "%%"))
	ui.PrintKeyValue("  Bits", fmt.Sprintf("%d", bits))
	ui.Success("RSA-%d keypair created on-card (private key non-exportable)", bits)

	return nil
}

func init() {
	pkcs11Cmd.AddCommand(pkcs11ListCmd)
	pkcs11ListCmd.Flags().StringVar(&pkcs11Module, "module", "", "Path to PKCS#11 module (.so); autodetected if omitted")

	pkcs11Cmd.AddCommand(pkcs11UseCmd)
	pkcs11UseCmd.Flags().StringVar(&pkcs11UseModule, "module", "", "Path to PKCS#11 module (.so); autodetected if omitted")
	pkcs11UseCmd.Flags().StringVar(&pkcs11UseURI, "uri", "", "PKCS#11 URI of the RSA key to enroll (required)")
	pkcs11UseCmd.Flags().StringVar(&pkcs11UsePinMode, "pin-mode", "prompt", "How to obtain the PIN: prompt, env, or none")
	pkcs11UseCmd.Flags().BoolVar(&pkcs11UseForce, "force", false, "Overwrite an existing machine identity")
	_ = pkcs11UseCmd.MarkFlagRequired("uri")

	pkcs11Cmd.AddCommand(pkcs11GenerateCmd)
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenModule, "module", "", "Path to PKCS#11 module (.so); autodetected if omitted")
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenToken, "token", "", "Token label to generate the key on (required)")
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenLabel, "label", "", "CKA_LABEL for the new key (required)")
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenID, "id", "", "CKA_ID for the new key, hex (e.g. 03) (required)")
	pkcs11GenerateCmd.Flags().IntVar(&pkcs11GenBits, "bits", 2048, "RSA modulus size in bits")
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenPinMode, "pin-mode", "prompt", "How to obtain the PIN: prompt, env, or none")
	_ = pkcs11GenerateCmd.MarkFlagRequired("token")
	_ = pkcs11GenerateCmd.MarkFlagRequired("label")
	_ = pkcs11GenerateCmd.MarkFlagRequired("id")

	rootCmd.AddCommand(pkcs11Cmd)
}
