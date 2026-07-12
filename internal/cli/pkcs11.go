//go:build pkcs11

package cli

import (
	"crypto/rsa"
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
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// selectOptionStdio is selectOption (see prompt.go) wired to the real terminal
// (os.Stdout/os.Stdin). It lives here, beside its only callers in the
// interactive pkcs11 wizard, so it shares their build tag; tests exercise
// selectOption directly with an injected reader/writer.
func selectOptionStdio(title string, options []string) (int, error) {
	return selectOption(os.Stdout, os.Stdin, title, options)
}

// ReadTokenPublicKey reads the RSA public key for the given PKCS#11 URI
// without logging in (see keyprovider.ReadTokenPublicKey). Used by
// `machine add --pkcs11`, which registers an existing on-card key's public
// half and never needs to decrypt anything.
func ReadTokenPublicKey(module, uri string) (*rsa.PublicKey, error) {
	return keyprovider.ReadTokenPublicKey(module, uri)
}

var pkcs11Module string

var pkcs11GenModule string
var pkcs11GenToken string
var pkcs11GenLabel string
var pkcs11GenID string
var pkcs11GenBits int
var pkcs11GenPinMode string

var pkcs11ImportModule string
var pkcs11ImportToken string
var pkcs11ImportLabel string
var pkcs11ImportID string
var pkcs11ImportFile string
var pkcs11ImportPinMode string

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
  nvolt pkcs11 list --pkcs11-module /usr/lib/softhsm/libsofthsm2.so`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// An explicit --pkcs11-module or NVOLT_PKCS11_MODULE targets a single module.
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
		ui.Warning("No PKCS#11 modules found (looked in common install locations); pass --pkcs11-module <path> or set NVOLT_PKCS11_MODULE")
		return nil
	}

	for _, m := range mods {
		printModuleListing(m)
		if err := runPKCS11List(m.Path); err != nil {
			ui.Warning("  Skipping %s: %s",
				strings.ReplaceAll(m.Path, "%", "%%"),
				strings.ReplaceAll(err.Error(), "%", "%%"))
		}
	}

	return nil
}

// printModuleListing renders one discovered module's header: the label at
// Info (the concise default), and the technical Path/Source at Verbose.
// ui.Verbose is a single-pass Printf (format+args, no re-parse), so a literal
// "%" in m.Path/m.Source needs no escaping when passed as a %s argument
// (unlike ui.PrintKeyValue -> ui.Info below, which double-formats).
func printModuleListing(m pkcs11.DiscoveredModule) {
	ui.Section(m.Label)
	ui.Verbose("  Path: %s", m.Path)
	ui.Verbose("  Source: %s", m.Source)
}

// runPKCS11List renders every token found on module, and that token's RSA
// keys. A token with zero RSA keys (e.g. a freshly-provisioned YubiKey PIV
// slot) is still rendered with a "no keys yet" hint instead of disappearing:
// previously a token with no keys produced no output at all, indistinguishable
// from the module having no card in it whatsoever.
func runPKCS11List(module string) error {
	tokens, err := pkcs11.ListTokensAndKeys(module)
	if err != nil {
		return fmt.Errorf("failed to list PKCS#11 keys: %w", err)
	}

	if len(tokens) == 0 {
		ui.Warning("No PKCS#11 token detected on module %s", module)
		return nil
	}

	ui.Section(fmt.Sprintf("Tokens (%d):", len(tokens)))
	for _, tok := range tokens {
		printTokenListing(tok)
	}

	return nil
}

// printTokenListing renders one token's header, then either its RSA keys or
// (when it has none yet) a short, actionable hint for creating one on that
// exact token so the card/token is always visibly detected, never silently
// indistinguishable from "no card present".
func printTokenListing(tok pkcs11.TokenListing) {
	// ui.PrintKeyValue -> ui.Info double-formats (see enrollPKCS11Machine/
	// runPKCS11Generate below): any "%" in card-derived token/key labels
	// gets reinterpreted as a format verb on the second pass. Escape
	// "%" -> "%%" for consistency with those sibling commands.
	ui.PrintKeyValue("  Token", ui.Cyan(strings.ReplaceAll(tok.Label, "%", "%%")))

	if len(tok.Keys) == 0 {
		// ui.Info here is a plain single-pass Printf (format+args, no
		// re-parse), so the raw (unescaped) token label is correct as a %s
		// argument: escaping it would print a literal "%%" in the command
		// example instead of "%".
		ui.Info("    No RSA key yet. Create one on the card with:")
		ui.Info("      nvolt pkcs11 generate --token %s --label nvolt --id 03 --bits 2048", tok.Label)
		ui.Info("    (On a YubiKey you can instead use: ykman piv keys generate --algorithm RSA2048 9d pub.pem")
		ui.Info("     && ykman piv certificates generate --subject \"CN=nvolt\" 9d pub.pem)")
		fmt.Println()
		return
	}

	for _, k := range tok.Keys {
		// Concise default: just the key's size. ui.Verbose is single-pass, so
		// the raw (unescaped) ID/Label are correct as %x/%s arguments here —
		// unlike the ui.PrintKeyValue/Info double-format pattern used above
		// for the token label.
		ui.Info("    RSA-%d", k.Bits)
		ui.Verbose("      ID: %x  Label: %s", k.ID, k.Label)
		fmt.Println()
	}
}

// enrollPKCS11Machine enrolls the on-card key at uri (via module) as this
// machine's identity, mirroring vault.InitializeMachine's machine-info
// construction but sourcing the keypair from the token instead of generating a
// software one. It is the fresh-enrollment path used by the --pkcs11 branch
// of init/join (via ensurePKCS11MachineInitialized); `nvolt rebind --pkcs11`
// swaps an already-enrolled machine's backing and calls keyprovider.Enroll
// directly instead, since it must preserve the existing machine-info rather
// than create a new identity.
func enrollPKCS11Machine(module, uri, pinMode string) error {
	if module == "" {
		return fmt.Errorf("no PKCS#11 module specified; use --pkcs11-module or set NVOLT_PKCS11_MODULE")
	}
	if uri == "" {
		return fmt.Errorf("no PKCS#11 URI specified; use --pkcs11-uri")
	}

	homePaths, err := vault.GetHomePaths()
	if err != nil {
		return err
	}

	// Never clobber an existing identity. Replacing one is intentionally not a
	// one-flag operation: overwriting machine-info would orphan every secret
	// wrapped to the current key (the master key is not re-wrapped here). To
	// re-enroll a different key, remove the identity below and start fresh;
	// migrating a software identity to hardware without losing access is a
	// separate, future flow that re-wraps the master key first.
	if vault.FileExists(homePaths.MachineInfo) {
		return fmt.Errorf("this machine already has an identity (%s); remove it to enroll a different key", homePaths.MachineInfo)
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

	// Offer a custom machine name, mirroring software init's first-time setup.
	// Gated on isInteractive() (like the module/token/key wizard) so scripted
	// and headless runs silently fall back to the hostname-derived default
	// rather than blocking on stdin. Prompted after enrollment so we never ask
	// a user to name a machine whose card/PIN just failed.
	customName := ""
	if isInteractive() {
		name, err := ui.PromptMachineName()
		if err != nil {
			return fmt.Errorf("failed to read machine name: %w", err)
		}
		customName = name
	}

	machineInfo := &types.MachineInfo{
		ID:          vault.GenerateMachineID(customName, hostname, fingerprint),
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

	// We only reach here when no machine-info existed, but a stray software
	// private_key.pem can still be on disk from a half-finished software init.
	// The identity is now backed by the card, so nothing needs that file
	// anymore, but nvolt never deletes a user's key file on their behalf
	// (same non-destructive principle as `nvolt rebind`): inform instead, and
	// let the user remove it once they've confirmed the card works.
	if vault.FileExists(homePaths.PrivateKey) {
		ui.Info("A software private key remains at %s; it can still decrypt your secrets.", homePaths.PrivateKey)
		ui.Info("Remove it once you've confirmed the card works: rm %s", homePaths.PrivateKey)
	}

	// Technical detail behind --verbose: ui.Verbose is a single-pass Printf
	// (format+args, no re-parse), so uri/module survive as plain %s
	// arguments with no escaping needed -- unlike the ui.PrintKeyValue ->
	// ui.Info double-format pattern used elsewhere in this file, a "%" byte
	// in uri (e.g. RFC7512 percent-encoded ids like "%01", present in
	// virtually every real pkcs11 URI) prints literally here.
	ui.Verbose("  Fingerprint: %s", machineInfo.Fingerprint)
	ui.Verbose("  Module: %s", module)
	ui.Verbose("  URI: %s", uri)
	ui.Verbose("  OAEP mode: %s", src.OAEPMode)
	ui.Success("Machine %s is now backed by the on-card key", machineInfo.ID)

	return nil
}

// isInteractive reports whether stdin is attached to a terminal. It gates the
// pkcs11 selection wizard below: a piped/redirected stdin (scripts, CI) must
// never block on a prompt, so every wizard step first checks this and errors
// instead of prompting when it is false.
//
// Uses mattn/go-isatty rather than golang.org/x/term.IsTerminal: on Windows,
// Git Bash/MSYS2/Cygwin shells give the process an MSYS pipe rather than a
// native console handle, which x/term.IsTerminal reports as "not a
// terminal" — wrongly refusing an interactive user there. go-isatty's
// IsCygwinTerminal detects that case in addition to native ttys.
func isInteractive() bool {
	fd := os.Stdin.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// resolveEnrollTarget resolves the PKCS#11 module path and key URI to enroll
// for the --pkcs11 branch of init/join. Explicit flags
// (or NVOLT_PKCS11_MODULE for the module) always win and never prompt, so the
// fully-explicit `--pkcs11-module X --pkcs11-uri Y` invocation behaves exactly as before
// with no TTY required. Only what is left unspecified falls back to
// autodetection/interactive selection, and the URI wizard only ever runs when
// stdin is a terminal.
func resolveEnrollTarget(flagModule, flagURI string) (module, uri string, err error) {
	module, err = resolveEnrollModule(flagModule)
	if err != nil {
		return "", "", err
	}

	if flagURI != "" {
		return module, flagURI, nil
	}

	uri, err = resolveEnrollURI(module)
	if err != nil {
		return "", "", err
	}
	return module, uri, nil
}

// resolveEnrollModule resolves the module path. An explicit --pkcs11-module flag or
// NVOLT_PKCS11_MODULE env var takes precedence (via pkcs11.ResolveModulePath,
// unchanged from before this wizard existed). Otherwise it defers to
// pkcs11.DetectModules: no modules found is an error (ResolveModulePath's,
// which lists every common location probed); exactly one is used without
// asking; more than one prompts (on a terminal) or errors listing the
// candidates (not a terminal).
func resolveEnrollModule(flagModule string) (string, error) {
	if flagModule != "" || os.Getenv("NVOLT_PKCS11_MODULE") != "" {
		return pkcs11.ResolveModulePath(flagModule)
	}

	mods := pkcs11.DetectModules()
	switch len(mods) {
	case 0:
		// Flag and env are both empty here, so this reproduces exactly the
		// "not found, looked in: ..." error DetectModules-backed autodetection
		// already produces.
		return pkcs11.ResolveModulePath("")
	case 1:
		return mods[0].Path, nil
	}

	if !isInteractive() {
		var b strings.Builder
		for _, m := range mods {
			fmt.Fprintf(&b, "\n  %s (%s)", m.Path, m.Label)
		}
		return "", fmt.Errorf("multiple PKCS#11 modules found; pass --pkcs11-module <path>:%s", b.String())
	}

	options := make([]string, len(mods))
	for i, m := range mods {
		options[i] = fmt.Sprintf("%s (%s)", m.Label, m.Path)
	}
	choice, err := selectOptionStdio("Multiple PKCS#11 modules found; choose one:", options)
	if err != nil {
		return "", fmt.Errorf("module selection: %w", err)
	}
	return mods[choice].Path, nil
}

// resolveEnrollURI runs the interactive key-selection wizard: it requires a
// terminal (a non-interactive caller must pass --pkcs11-uri instead), lists the RSA
// keys visible on module, narrows to a token (prompting if more than one),
// narrows to a key on that token (prompting if more than one), and builds the
// pkcs11: URI for the selection.
func resolveEnrollURI(module string) (string, error) {
	if !isInteractive() {
		return "", fmt.Errorf("no --pkcs11-uri given and not a terminal; pass --pkcs11-uri 'pkcs11:token=...;id=...'")
	}

	keys, err := pkcs11.ListRSAKeys(module)
	if err != nil {
		return "", fmt.Errorf("failed to list PKCS#11 keys: %w", err)
	}
	if len(keys) == 0 {
		return "", fmt.Errorf("no RSA keys found on %s", module)
	}

	tokenLabel, err := selectToken(keys)
	if err != nil {
		return "", err
	}

	var onToken []pkcs11.KeyInfo
	for _, k := range keys {
		if k.TokenLabel == tokenLabel {
			onToken = append(onToken, k)
		}
	}

	key, err := selectKey(onToken)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("pkcs11:token=%s;id=%s;type=private",
		pctEncodePKCS11Attr(tokenLabel), pctEncodeID(key.ID)), nil
}

// selectToken narrows keys to a single token label: the one label present, or
// (when more than one token has RSA keys) a wizard prompt among the distinct
// labels in first-seen order.
func selectToken(keys []pkcs11.KeyInfo) (string, error) {
	var labels []string
	seen := map[string]bool{}
	for _, k := range keys {
		if !seen[k.TokenLabel] {
			seen[k.TokenLabel] = true
			labels = append(labels, k.TokenLabel)
		}
	}
	if len(labels) == 1 {
		return labels[0], nil
	}
	choice, err := selectOptionStdio("Multiple tokens found; choose one:", labels)
	if err != nil {
		return "", fmt.Errorf("token selection: %w", err)
	}
	return labels[choice], nil
}

// selectKey narrows onToken (already filtered to a single token) to a single
// key: the one key present, or a wizard prompt among them otherwise.
func selectKey(onToken []pkcs11.KeyInfo) (pkcs11.KeyInfo, error) {
	if len(onToken) == 1 {
		return onToken[0], nil
	}
	options := make([]string, len(onToken))
	for i, k := range onToken {
		options[i] = fmt.Sprintf("%s (id=%x, %d-bit)", k.Label, k.ID, k.Bits)
	}
	choice, err := selectOptionStdio("Multiple keys found on token; choose one:", options)
	if err != nil {
		return pkcs11.KeyInfo{}, fmt.Errorf("key selection: %w", err)
	}
	return onToken[choice], nil
}

// pctEncodePKCS11Attr percent-encodes s for use as an RFC7512 pkcs11 URI
// attribute value (e.g. token=): bytes outside the URI "unreserved" set
// (RFC 3986 SS2.3: ALPHA / DIGIT / "-" "." "_" "~") are escaped as %XX so
// delimiters like ";", "%" and space survive round-tripping through
// keyprovider's parsePKCS11URI, which decodes attribute values with
// url.PathUnescape.
func pctEncodePKCS11Attr(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreservedPKCS11Byte(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// isUnreservedPKCS11Byte reports whether c needs no percent-escaping in an
// RFC7512 pkcs11 URI attribute value.
func isUnreservedPKCS11Byte(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '.' || c == '_' || c == '~':
		return true
	default:
		return false
	}
}

// pctEncodeID renders raw key-id bytes as RFC7512 id= percent-escapes, one
// %XX per byte regardless of whether the byte would otherwise print (e.g.
// []byte{0x01} -> "%01"), matching the CKA_ID convention used throughout this
// package (hex, e.g. --id 03 in `pkcs11 generate`) and round-tripping through
// parsePKCS11URI's url.PathUnescape.
func pctEncodeID(id []byte) string {
	var b strings.Builder
	for _, by := range id {
		fmt.Fprintf(&b, "%%%02x", by)
	}
	return b.String()
}

var pkcs11GenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate an RSA keypair on a PKCS#11 token",
	Long: `Generate an RSA keypair directly on a PKCS#11 token (SoftHSM, and
tokens that expose C_GenerateKeyPair). The private key never leaves the device.

Example:
  nvolt pkcs11 generate --pkcs11-module /usr/lib/softhsm/libsofthsm2.so \
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

	// ui.Success -> ui.Info double-formats (Success's own Sprintf embeds its
	// args, then Info re-parses the result as a format string with none): any
	// "%" in the user-supplied token gets reinterpreted as a format verb on
	// the second pass, so escape "%" -> "%%" on it here. ui.Verbose below is a
	// single-pass Printf, so Label/ID need no such escaping when passed as
	// %s/%x arguments.
	ui.Success("RSA-%d keypair created on-card on token %s (private key non-exportable)",
		bits, strings.ReplaceAll(token, "%", "%%"))
	ui.Verbose("  Label: %s", label)
	ui.Verbose("  ID: %x", id)
	ui.Verbose("  Bits: %d", bits)

	return nil
}

var pkcs11ImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an RSA private key onto a token (PKCS#11 C_CreateObject)",
	Long: `Import an existing RSA private key (PEM) onto a PKCS#11 token via
C_CreateObject. Not every token supports this (e.g. a YubiKey via OpenSC
refuses PKCS#11 key import; use the device's own tool instead).

Example:
  nvolt pkcs11 import --pkcs11-module /usr/lib/softhsm/libsofthsm2.so \
    --token nvolt-test --label my-key --id 03 --privkey key.pem`,
	RunE: func(cmd *cobra.Command, args []string) error {
		module, err := pkcs11.ResolveModulePath(pkcs11ImportModule)
		if err != nil {
			return err
		}
		return runPKCS11Import(module, pkcs11ImportToken, pkcs11ImportLabel, pkcs11ImportID, pkcs11ImportFile, pkcs11ImportPinMode)
	},
}

// runPKCS11Import opens a session on the named token, logs in, and imports an
// RSA private key read from keyFile via C_CreateObject.
func runPKCS11Import(module, token, label, idHex, keyFile, pinMode string) error {
	if token == "" || keyFile == "" {
		return fmt.Errorf("--token and --privkey are required")
	}
	pemData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", keyFile, err)
	}
	priv, err := nvcrypto.DecodePrivateKeyPEM(pemData)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	if priv.N.BitLen() < 2048 {
		return fmt.Errorf("RSA key is %d bits; minimum 2048 required", priv.N.BitLen())
	}
	id, err := hex.DecodeString(idHex)
	if err != nil {
		return fmt.Errorf("invalid --id hex %q: %w", idHex, err)
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

	if _, err := sess.ImportRSAPrivateKey(label, id, priv); err != nil {
		return err
	}
	// ui.Success -> ui.Info double-formats (see runPKCS11Generate above):
	// escape "%" -> "%%" on the user-controlled token before display. The
	// ui.Verbose calls below are single-pass Printf (format+args, no
	// re-parse), so label needs no such escaping when passed as a %s
	// argument -- escaping it here would print a literal "%%" instead of "%".
	ui.Success("Imported RSA key onto token %s", strings.ReplaceAll(token, "%", "%%"))
	ui.Verbose("  Label: %s", label)
	ui.Verbose("  ID: %x", id)
	return nil
}

func init() {
	pkcs11Cmd.AddCommand(pkcs11ListCmd)
	pkcs11ListCmd.Flags().StringVar(&pkcs11Module, "pkcs11-module", "", "Path to PKCS#11 module (.so); autodetected if omitted")

	pkcs11Cmd.AddCommand(pkcs11GenerateCmd)
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenModule, "pkcs11-module", "", "Path to PKCS#11 module (.so); autodetected if omitted")
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenToken, "token", "", "Token label to generate the key on (required)")
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenLabel, "label", "", "CKA_LABEL for the new key (required)")
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenID, "id", "", "CKA_ID for the new key, hex (e.g. 03) (required)")
	pkcs11GenerateCmd.Flags().IntVar(&pkcs11GenBits, "bits", 2048, "RSA modulus size in bits")
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenPinMode, "pkcs11-pin-mode", "prompt", "How to obtain the PIN: prompt, env, or none")
	_ = pkcs11GenerateCmd.MarkFlagRequired("token")
	_ = pkcs11GenerateCmd.MarkFlagRequired("label")
	_ = pkcs11GenerateCmd.MarkFlagRequired("id")

	pkcs11Cmd.AddCommand(pkcs11ImportCmd)
	pkcs11ImportCmd.Flags().StringVar(&pkcs11ImportModule, "pkcs11-module", "", "Path to PKCS#11 module (.so); autodetected if omitted")
	pkcs11ImportCmd.Flags().StringVar(&pkcs11ImportToken, "token", "", "Token label to import the key onto (required)")
	pkcs11ImportCmd.Flags().StringVar(&pkcs11ImportLabel, "label", "", "CKA_LABEL for the imported key (required)")
	pkcs11ImportCmd.Flags().StringVar(&pkcs11ImportID, "id", "", "CKA_ID for the imported key, hex (e.g. 03) (required)")
	pkcs11ImportCmd.Flags().StringVar(&pkcs11ImportFile, "privkey", "", "Path to the RSA private key PEM to import (required)")
	pkcs11ImportCmd.Flags().StringVar(&pkcs11ImportPinMode, "pkcs11-pin-mode", "prompt", "How to obtain the PIN: prompt, env, or none")
	_ = pkcs11ImportCmd.MarkFlagRequired("token")
	_ = pkcs11ImportCmd.MarkFlagRequired("label")
	_ = pkcs11ImportCmd.MarkFlagRequired("id")
	_ = pkcs11ImportCmd.MarkFlagRequired("privkey")

	rootCmd.AddCommand(pkcs11Cmd)
}
