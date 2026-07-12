//go:build pkcs11 || tpm_static

package cli

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	"golang.org/x/term"
)

// selectOptionStdio is the interactive selection wired to the real terminal
// (os.Stdout/os.Stdin). It lives here, beside its only callers in the pkcs11
// wizard, so it shares their build tag; tests exercise selectOption directly
// with an injected reader/writer.
//
// On a real terminal it reads the choice through golang.org/x/term — the same
// native-console path pinentry.Read uses — because bufio.Scanner on os.Stdin
// does NOT accept input on the Windows console (the process hangs at the
// prompt). When stdin is not a real terminal (an MSYS/Cygwin pipe, a redirected
// file, or a test's injected reader), it falls back to selectOption's plain
// bufio line reader, which works there and keeps selectOption unit-testable.
func selectOptionStdio(title string, options []string) (int, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return selectOptionViaTerm(title, options)
	}
	return selectOption(os.Stdout, os.Stdin, title, options)
}

// selectOptionViaTerm renders the same numbered menu as selectOption but reads
// the choice with term.ReadPassword (no echo), mirroring exactly how
// pinentry.Read collects the PIN via the native console API — the one input
// path proven to work on the Windows console. Because the read is not echoed,
// it echoes the resolved choice back ("→ selected: [n] label") so the user sees
// what they picked; reading a short menu number without echo is an acceptable
// price for reusing the proven path rather than adding new Windows console code.
func selectOptionViaTerm(title string, options []string) (int, error) {
	if len(options) == 0 {
		return 0, fmt.Errorf("selectOption: no options to choose from")
	}
	_, _ = fmt.Fprintln(os.Stdout, title)
	for i, opt := range options {
		_, _ = fmt.Fprintf(os.Stdout, "  [%d] %s\n", i+1, opt)
	}
	for attempt := 0; attempt < maxSelectAttempts; attempt++ {
		_, _ = fmt.Fprint(os.Stdout, "Enter a number: ")
		line, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(os.Stdout) // ReadPassword swallows the newline; restore it
		if err != nil {
			return 0, fmt.Errorf("selectOption: reading input: %w", err)
		}
		s := strings.TrimSpace(string(line))
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > len(options) {
			_, _ = fmt.Fprintf(os.Stdout, "invalid selection %q; enter a number between 1 and %d\n", s, len(options))
			continue
		}
		_, _ = fmt.Fprintf(os.Stdout, "→ selected: [%d] %s\n", n, options[n-1])
		return n - 1, nil
	}
	return 0, fmt.Errorf("selectOption: too many invalid selections")
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
	Use:   pkcs11Name,
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
		// `pkcs11 list` is where the embedded wolfPKCS11 module's TPM device caps
		// banner is wanted (it identifies the TPM behind the token), so enable it
		// even at the default output level. build-module.sh gates that upstream
		// printf behind NVOLT_TPM_CAPS; set it before any C_Initialize, only when
		// unset so an operator-provided value still wins.
		if os.Getenv("NVOLT_TPM_CAPS") == "" {
			_ = os.Setenv("NVOLT_TPM_CAPS", "1")
		}

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

// printModuleListing renders one discovered module's header: the concise,
// user-facing Name at Info (the default), and the technical Label/Path/Source
// at Verbose. ui.Verbose is a single-pass Printf (format+args, no re-parse), so
// a literal "%" in m.Label/m.Path/m.Source needs no escaping when passed as a
// %s argument (unlike ui.PrintKeyValue -> ui.Info below, which double-formats).
func printModuleListing(m pkcs11.DiscoveredModule) {
	ui.Section(m.Name)
	ui.Verbose("  Module: %s", m.Label)
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
		// In verbose mode on an interactive terminal, offer to log in and reveal
		// the real size + fingerprint of any key whose modulus the token hid
		// pre-login (Bits==0). Plain `list` and non-interactive runs are
		// untouched; a token with nothing hidden never prompts.
		tok = maybeRevealHiddenKeys(module, tok)
		printTokenListing(tok, module)
	}

	return nil
}

// hasHiddenKey reports whether any key in keys had its size hidden by the token
// during no-login discovery (Bits == 0), i.e. whether a login would reveal more.
func hasHiddenKey(keys []pkcs11.KeyInfo) bool {
	for _, k := range keys {
		if k.Bits == 0 {
			return true
		}
	}
	return false
}

// maybeRevealHiddenKeys is the interactive, verbose-only PIN-reveal step for
// `pkcs11 list -v`. When the output level is Verbose, stdin is an interactive
// terminal, and tok has at least one key whose size the token hid pre-login
// (Bits==0), it prompts ONCE for the token PIN, logs in, and re-reads each
// hidden key's public modulus so the real RSA-<bits> and fingerprint can be
// shown (via pkcs11.FillHiddenKeyInfo).
//
// It NEVER fails the listing: outside verbose mode, off a terminal, or when
// nothing is hidden it returns tok unchanged with no prompt; and a
// declined/empty PIN or any login/read error is swallowed (logged at verbose)
// so the affected keys simply keep the Task 2 "size hidden" display. SoftHSM /
// YubiKey, which expose the modulus pre-login, have nothing hidden and so never
// prompt — this is exercised by build + code review and the embedded harness,
// not by CI (where SoftHSM reveals the modulus without a login).
func maybeRevealHiddenKeys(module string, tok pkcs11.TokenListing) pkcs11.TokenListing {
	if ui.GetLevel() < ui.LevelVerbose || !isInteractive() || !hasHiddenKey(tok.Keys) {
		return tok
	}

	// ui.Info is single-pass Printf (format+args), so a "%" in the token label
	// is safe as a plain %s argument with no escaping.
	ui.Info("  Token %q hides key sizes until login; enter its PIN to reveal them (or leave blank to skip).", tok.Label)
	pin, err := pinentry.Read("prompt")
	if err != nil || pin == "" {
		return tok
	}

	filled, err := pkcs11.FillHiddenKeyInfo(module, tok.Label, pin, tok.Keys)
	if err != nil {
		ui.Verbose("  Could not reveal key sizes on %q: %s", tok.Label, err.Error())
		return tok
	}
	tok.Keys = filled
	return tok
}

// printTokenListing renders one token's header, then either its RSA keys or
// (when it has none yet) a short, actionable hint for creating one on that
// exact token so the card/token is always visibly detected, never silently
// indistinguishable from "no card present". module is the path this token was
// discovered on (e.g. the "embedded" sentinel for the built-in wolfPKCS11
// module); it is baked into the generate hint so the command targets the right
// provider — generate's own module resolution otherwise silently defaults to a
// single installed module (often OpenSC) and would miss this token.
func printTokenListing(tok pkcs11.TokenListing, module string) {
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
		ui.Info("      nvolt pkcs11 generate --pkcs11-module %s --token %s", module, tok.Label)
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
		//
		// Bits==0 means the token hid CKA_MODULUS during no-login discovery
		// (e.g. wolfPKCS11 before a PIN): print an honest "size hidden" line
		// rather than a misleading "RSA-0". `list -v` on a terminal offers to
		// log in and fill in the real size (see maybeRevealHiddenKeys).
		if k.Bits > 0 {
			ui.Info("    RSA-%d", k.Bits)
		} else {
			ui.Info("    RSA (size hidden — login to view)")
		}
		ui.Verbose("      ID: %x  Label: %s", k.ID, k.Label)
		// The public-key fingerprint (same "SHA256:<base64>" shown as
		// "Fingerprint:" during init) lets a user match a token key to a
		// machine's identity. Verbose-only, and only when discovery could read
		// the public half (empty otherwise). ui.Verbose is single-pass Printf,
		// so the fingerprint (base64, no "%") is safe as a plain %s argument.
		if k.Fingerprint != "" {
			ui.Verbose("      Fingerprint: %s", k.Fingerprint)
		}
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
// identityPub, when non-nil (the rebind path), pins the wizard to the machine's
// existing identity public key: only on-card keys whose public half matches are
// offered, so rebind can never point the machine at a different key. It is nil
// for a fresh enrollment (init/join/machine add), where every key is a valid
// choice.
func resolveEnrollTarget(flagModule, flagURI string, identityPub *rsa.PublicKey) (module, uri string, err error) {
	// An explicit --pkcs11-uri fully specifies the key: resolve only the module
	// (explicit flag/env, or a single autodetected module, or the module picker
	// when several exist) and return, with no token/key wizard. This is the
	// non-interactive contract scripts/CI depend on.
	if flagURI != "" {
		module, err = resolveEnrollModule(flagModule)
		if err != nil {
			return "", "", err
		}
		return module, flagURI, nil
	}

	// No URI: run the flattened cross-module token picker, which resolves the
	// module and token together (and then the key on it).
	return resolveEnrollFlattened(flagModule, identityPub)
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
			fmt.Fprintf(&b, "\n  %s (%s)", m.Path, m.Name)
		}
		return "", fmt.Errorf("multiple PKCS#11 modules found; pass --pkcs11-module <path>:%s", b.String())
	}

	options := make([]string, len(mods))
	for i, m := range mods {
		options[i] = fmt.Sprintf("%s (%s)", m.Name, m.Path)
	}
	choice, err := selectOptionStdio("Multiple PKCS#11 modules found; choose one:", options)
	if err != nil {
		return "", fmt.Errorf("module selection: %w", err)
	}
	return mods[choice].Path, nil
}

// enrollTokenChoice is one (module, token) pair offered by the flattened
// enrollment picker: the module the token was discovered on (path or
// "embedded"/"builtin" sentinel), the module's concise display name, the token
// label, and the RSA keys visible on it (used for the subsequent key step and
// the rebind identity filter).
type enrollTokenChoice struct {
	module     string
	moduleName string
	label      string
	keys       []pkcs11.KeyInfo
}

// resolveEnrollFlattened runs the flattened enrollment wizard: it presents ONE
// numbered list of tokens across every detected module (like `pkcs11 list`),
// lets the user pick a token, and derives both the module and — after the key
// step — the pkcs11: URI from that single choice. It requires a terminal (a
// non-interactive caller must pass --pkcs11-uri instead). An explicit
// --pkcs11-module (or NVOLT_PKCS11_MODULE) restricts the scan to that one
// module; otherwise every module DetectModules finds is scanned, and a module
// that fails to open is skipped with a warning (as `pkcs11 list` does) rather
// than aborting. If exactly one candidate token exists it is auto-selected with
// no prompt; the key step within the token is unchanged, including the rebind
// identityPub filter.
func resolveEnrollFlattened(flagModule string, identityPub *rsa.PublicKey) (module, uri string, err error) {
	if !isInteractive() {
		return "", "", fmt.Errorf("no --pkcs11-uri given and not a terminal; pass --pkcs11-uri 'pkcs11:token=...;id=...'")
	}

	// Which modules to scan: an explicit module/env restricts to that one;
	// otherwise every detected module.
	var mods []pkcs11.DiscoveredModule
	if flagModule != "" || os.Getenv("NVOLT_PKCS11_MODULE") != "" {
		path, rerr := pkcs11.ResolveModulePath(flagModule)
		if rerr != nil {
			return "", "", rerr
		}
		mods = []pkcs11.DiscoveredModule{{Path: path, Name: filepath.Base(path), Label: path}}
	} else {
		mods = pkcs11.DetectModules()
		if len(mods) == 0 {
			// Reproduce ResolveModulePath's "not found, looked in: ..." error.
			_, rerr := pkcs11.ResolveModulePath("")
			if rerr != nil {
				return "", "", rerr
			}
			return "", "", fmt.Errorf("no PKCS#11 modules found; pass --pkcs11-module <path> or set NVOLT_PKCS11_MODULE")
		}
	}

	// Enumerate tokens across the modules, skipping any that fail to open (a bad
	// provider must not abort the picker) and any token with no RSA key yet
	// (nothing to enroll), exactly as the old per-module wizard did by listing
	// keys rather than empty tokens.
	var toks []enrollTokenChoice
	for _, m := range mods {
		tokens, lerr := pkcs11.ListTokensAndKeys(m.Path)
		if lerr != nil {
			ui.Warning("Skipping %s: %s",
				strings.ReplaceAll(m.Name, "%", "%%"),
				strings.ReplaceAll(lerr.Error(), "%", "%%"))
			continue
		}
		for _, t := range tokens {
			if len(t.Keys) == 0 {
				continue
			}
			toks = append(toks, enrollTokenChoice{module: m.Path, moduleName: m.Name, label: t.Label, keys: t.Keys})
		}
	}

	// Rebind (identityPub != nil) narrows the token list to those holding a key
	// that matches this machine's identity, so the token step can never point
	// rebind at a token without the right key (and a sole match still
	// auto-selects, preserving the no-prompt rebind path).
	if identityPub != nil {
		var kept []enrollTokenChoice
		for _, t := range toks {
			if len(filterKeysMatchingIdentity(t.module, t.keys, identityPub)) > 0 {
				kept = append(kept, t)
			}
		}
		toks = kept
	}

	if len(toks) == 0 {
		if identityPub != nil {
			return "", "", fmt.Errorf("no token holding a key matching this machine's identity was found; " +
				"put your key on the card first (nvolt pkcs11 import --privkey <your-key.pem> --token <label>, " +
				"or on a YubiKey: ykman piv keys import <slot> <your-key.pem>), then re-run")
		}
		return "", "", fmt.Errorf("no PKCS#11 token with an RSA key was found; create one with 'nvolt pkcs11 generate' or pass --pkcs11-uri")
	}

	// Pick the token (auto-select the sole candidate).
	var chosen enrollTokenChoice
	if len(toks) == 1 {
		chosen = toks[0]
	} else {
		options := make([]string, len(toks))
		for i, t := range toks {
			options[i] = fmt.Sprintf("%s (%s)", t.label, t.moduleName)
		}
		choice, serr := selectOptionStdio("Choose a token to enroll:", options)
		if serr != nil {
			return "", "", fmt.Errorf("token selection: %w", serr)
		}
		chosen = toks[choice]
	}

	uri, err = selectKeyURIOnToken(chosen, identityPub)
	if err != nil {
		return "", "", err
	}
	return chosen.module, uri, nil
}

// selectKeyURIOnToken resolves the pkcs11: URI for a key on the already-chosen
// token. It is the unchanged key-selection step: for rebind (identityPub !=
// nil) it filters to keys whose on-card public key matches the machine's
// identity — a sole match auto-selects, several narrow the prompt, zero errors
// with the import hint — and for a fresh enrollment (identityPub == nil) it
// offers every key on the token (auto-selecting a sole key).
func selectKeyURIOnToken(t enrollTokenChoice, identityPub *rsa.PublicKey) (string, error) {
	keys := t.keys
	if identityPub != nil {
		matches := filterKeysMatchingIdentity(t.module, keys, identityPub)
		switch len(matches) {
		case 0:
			return "", fmt.Errorf("no key matching this machine's identity was found on token %q; "+
				"put your key on the card first (nvolt pkcs11 import --privkey <your-key.pem> --token <label>, "+
				"or on a YubiKey: ykman piv keys import <slot> <your-key.pem>), then re-run", t.label)
		case 1:
			k := matches[0]
			return buildPKCS11URI(k.TokenLabel, k.ID), nil
		default:
			keys = matches
		}
	}

	key, err := selectKey(keys)
	if err != nil {
		return "", err
	}
	return buildPKCS11URI(key.TokenLabel, key.ID), nil
}

// buildPKCS11URI renders the private-key pkcs11: URI for a token label and key
// id, percent-encoding both per RFC7512 so they round-trip through
// keyprovider.ParsePKCS11URI. It is the single source of the URI shape used by
// the wizard and the identity filter.
func buildPKCS11URI(tokenLabel string, id []byte) string {
	return fmt.Sprintf("pkcs11:token=%s;id=%s;type=private",
		pctEncodePKCS11Attr(tokenLabel), pctEncodeID(id))
}

// filterKeysMatchingIdentity returns the subset of keys whose on-card public
// key equals identityPub (via samePublicKey). It reads each candidate's public
// key with ReadTokenPublicKey — no login needed, since public-key objects are
// visible pre-login — building the same pkcs11: URI the wizard would. A key
// whose public half can't be read is skipped: it can't be confirmed as the
// identity key, and offering it would risk the very mismatch this filter
// exists to prevent.
func filterKeysMatchingIdentity(module string, keys []pkcs11.KeyInfo, identityPub *rsa.PublicKey) []pkcs11.KeyInfo {
	var out []pkcs11.KeyInfo
	for _, k := range keys {
		pub, err := ReadTokenPublicKey(module, buildPKCS11URI(k.TokenLabel, k.ID))
		if err != nil {
			continue
		}
		if samePublicKey(pub, identityPub) {
			out = append(out, k)
		}
	}
	return out
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

// resolveModuleForToken resolves which PKCS#11 module a --token command
// (generate/import) should act on, so that naming a token without a
// --pkcs11-module targets the module that actually hosts that token instead of
// silently defaulting to a single installed provider (often OpenSC), which
// would then fail with "no token with label ...".
//
// Precedence:
//   - An explicit flagModule, or NVOLT_PKCS11_MODULE being set, always wins and
//     is resolved via pkcs11.ResolveModulePath exactly as before.
//   - Otherwise, when a token label is given, every discovered module
//     (pkcs11.DetectModules) is scanned with the same no-login discovery
//     `pkcs11 list` uses (pkcs11.ListTokensAndKeys) and matched by token label.
//     A module that fails to open is skipped with a warning, as list does. This
//     also matches a blank/uninitialized token that generate will auto-create:
//     ListTokensAndKeys reports the token even with zero keys, so its label
//     still matches. Exactly one hosting module is used; several is an error
//     listing the candidates; none falls back to ResolveModulePath("") so the
//     pre-existing "single default module / not-found" behavior and error are
//     preserved unchanged.
func resolveModuleForToken(flagModule, token string) (string, error) {
	if flagModule != "" || os.Getenv("NVOLT_PKCS11_MODULE") != "" {
		return pkcs11.ResolveModulePath(flagModule)
	}
	if token == "" {
		return pkcs11.ResolveModulePath("")
	}

	var hosting []pkcs11.DiscoveredModule
	for _, m := range pkcs11.DetectModules() {
		tokens, err := pkcs11.ListTokensAndKeys(m.Path)
		if err != nil {
			ui.Warning("Skipping %s: %s",
				strings.ReplaceAll(m.Name, "%", "%%"),
				strings.ReplaceAll(err.Error(), "%", "%%"))
			continue
		}
		for _, t := range tokens {
			if t.Label == token {
				hosting = append(hosting, m)
				break
			}
		}
	}

	switch len(hosting) {
	case 1:
		return hosting[0].Path, nil
	case 0:
		// No discovered module hosts the token; fall back to the default
		// resolution so the existing "single default module / not found" error
		// (e.g. "no token with label ...") is preserved unchanged.
		return pkcs11.ResolveModulePath("")
	default:
		var b strings.Builder
		for _, m := range hosting {
			fmt.Fprintf(&b, "\n  %s (%s)", m.Path, m.Name)
		}
		return "", fmt.Errorf("token %q found on multiple modules; pass --pkcs11-module:%s", token, b.String())
	}
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
		module, err := resolveModuleForToken(pkcs11GenModule, pkcs11GenToken)
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
		label = "nvolt"
	}
	// An explicit --id must be valid, non-empty hex. An omitted --id (idHex == "")
	// is auto-picked from the token's free id space once we can see its keys.
	var explicitID []byte
	if idHex != "" {
		decoded, derr := hex.DecodeString(idHex)
		if derr != nil {
			return fmt.Errorf("invalid --id (must be hex, e.g. 03): %w", derr)
		}
		if len(decoded) == 0 {
			return fmt.Errorf("invalid --id: decodes to empty; omit --id to auto-assign, or pass hex like 03")
		}
		explicitID = decoded
	}
	if bits < 2048 {
		return fmt.Errorf("--bits must be at least 2048 (got %d)", bits)
	}

	m, err := pkcs11.Open(module)
	if err != nil {
		return fmt.Errorf("failed to open PKCS#11 module: %w", err)
	}
	defer func() { _ = m.Close() }()

	pin, err := pinentry.Read(pinMode)
	if err != nil {
		return fmt.Errorf("failed to obtain PIN: %w", err)
	}

	// Auto-initialize a blank token (never initialized, or no user PIN yet) so a
	// fresh card is usable in one step. A token that is already live is left
	// untouched — its keys are never wiped (see EnsureTokenInitialized). Done
	// before opening the working session, since C_InitToken requires no open
	// session on the token.
	if _, err := m.EnsureTokenInitialized(token, pin, func() {
		ui.Info("Initializing fresh PKCS#11 token %q…", token)
	}); err != nil {
		return fmt.Errorf("failed to initialize token %q: %w", token, err)
	}

	sess, err := m.OpenSessionRW(token)
	if err != nil {
		return fmt.Errorf("failed to open session on token %q: %w", token, err)
	}
	defer func() { _ = sess.Close() }()

	if pin != "" {
		if err := sess.Login(pin); err != nil {
			return fmt.Errorf("failed to log in: %w", err)
		}
	}

	// Resolve the key id: honor an explicit --id (rejecting a collision with an
	// existing key), or auto-pick the lowest unused single-byte id on the token.
	existing := sess.ListKeyIDs()
	id := explicitID
	if id == nil {
		id = nextFreeKeyID(existing)
		idHex = hex.EncodeToString(id)
	} else if containsID(existing, id) {
		return fmt.Errorf("a key with id %s already exists on token %q; pass a different --id", idHex, token)
	}

	if _, err := sess.GenerateRSAKeyPair(label, id, bits); err != nil {
		return fmt.Errorf("failed to generate RSA keypair: %w", err)
	}

	// Headline via ui.Success, which double-formats (Sprintf then Info re-parses),
	// so the user-controlled token/label are "%"->"%%" escaped; idHex is hex-only
	// and bits an int, so both are safe unescaped.
	ui.Success("Created RSA-%d key  label=%s  id=%s  on token %s",
		bits,
		strings.ReplaceAll(label, "%", "%%"),
		idHex,
		strings.ReplaceAll(token, "%", "%%"))

	// Point the user at how to adopt this exact key as the machine identity.
	// ui.Info is single-pass Printf (format+args), so module and the "%"-bearing
	// pkcs11 URI survive literally as %s arguments with no escaping.
	uri := fmt.Sprintf("pkcs11:token=%s;id=%s;type=private",
		pctEncodePKCS11Attr(token), pctEncodeID(id))
	ui.Info("Use this key as this machine's identity:")
	ui.Info("  nvolt init --pkcs11 --pkcs11-module %s --pkcs11-uri '%s'", module, uri)

	ui.Verbose("  Bits: %d", bits)

	return nil
}

// containsID reports whether id appears in ids (exact byte-equality).
func containsID(ids [][]byte, id []byte) bool {
	for _, x := range ids {
		if bytes.Equal(x, id) {
			return true
		}
	}
	return false
}

// nextFreeKeyID picks the lowest unused single-byte CKA_ID starting at 0x01,
// given the ids already on the token: a fresh token yields 0x01, a second key
// 0x02, and so on. Multi-byte ids don't constrain the single-byte space, so they
// are ignored. If all 255 single-byte ids are taken (pathological), it falls
// back to 0x01 (GenerateRSAKeyPair then surfaces any real collision).
func nextFreeKeyID(existing [][]byte) []byte {
	used := map[byte]bool{}
	for _, id := range existing {
		if len(id) == 1 {
			used[id[0]] = true
		}
	}
	for b := 1; b <= 0xff; b++ {
		if !used[byte(b)] {
			return []byte{byte(b)}
		}
	}
	return []byte{0x01}
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
		module, err := resolveModuleForToken(pkcs11ImportModule, pkcs11ImportToken)
		if err != nil {
			return err
		}
		return runPKCS11Import(module, pkcs11ImportToken, pkcs11ImportLabel, pkcs11ImportID, pkcs11ImportFile, pkcs11ImportPinMode)
	},
}

// runPKCS11Import opens a session on the named token, logs in, and imports an
// RSA private key read from keyFile via C_CreateObject. Its --label / --id
// handling and success/next-step output are IDENTICAL to runPKCS11Generate — the
// two commands differ only in where the key comes from (created on-card vs loaded
// from a PEM): label defaults to "nvolt", an omitted --id auto-assigns the next
// free CKA_ID (an explicit --id that collides is rejected), and on success it
// prints the chosen label+id plus the copy-paste `nvolt init --pkcs11` line.
func runPKCS11Import(module, token, label, idHex, keyFile, pinMode string) error {
	if token == "" {
		return fmt.Errorf("no PKCS#11 token specified; use --token")
	}
	if keyFile == "" {
		return fmt.Errorf("no private key specified; use --privkey")
	}
	if label == "" {
		label = "nvolt"
	}
	// An explicit --id must be valid, non-empty hex. An omitted --id (idHex == "")
	// is auto-picked from the token's free id space once we can see its keys —
	// exactly as runPKCS11Generate does.
	var explicitID []byte
	if idHex != "" {
		decoded, derr := hex.DecodeString(idHex)
		if derr != nil {
			return fmt.Errorf("invalid --id (must be hex, e.g. 03): %w", derr)
		}
		if len(decoded) == 0 {
			return fmt.Errorf("invalid --id: decodes to empty; omit --id to auto-assign, or pass hex like 03")
		}
		explicitID = decoded
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

	m, err := pkcs11.Open(module)
	if err != nil {
		return fmt.Errorf("failed to open PKCS#11 module: %w", err)
	}
	defer func() { _ = m.Close() }()

	pin, err := pinentry.Read(pinMode)
	if err != nil {
		return fmt.Errorf("failed to obtain PIN: %w", err)
	}

	// Auto-initialize a blank token before importing, mirroring generate; a live
	// token is left untouched. Done before opening the working session because
	// C_InitToken requires no session open on the token.
	if _, err := m.EnsureTokenInitialized(token, pin, func() {
		ui.Info("Initializing fresh PKCS#11 token %q…", token)
	}); err != nil {
		return fmt.Errorf("failed to initialize token %q: %w", token, err)
	}

	sess, err := m.OpenSessionRW(token)
	if err != nil {
		return fmt.Errorf("failed to open session on token %q: %w", token, err)
	}
	defer func() { _ = sess.Close() }()

	if pin != "" {
		if err := sess.Login(pin); err != nil {
			return fmt.Errorf("failed to log in: %w", err)
		}
	}

	// Resolve the key id: honor an explicit --id (rejecting a collision with an
	// existing key), or auto-pick the lowest unused single-byte id on the token —
	// identical to runPKCS11Generate.
	existing := sess.ListKeyIDs()
	id := explicitID
	if id == nil {
		id = nextFreeKeyID(existing)
		idHex = hex.EncodeToString(id)
	} else if containsID(existing, id) {
		return fmt.Errorf("a key with id %s already exists on token %q; pass a different --id", idHex, token)
	}

	if _, err := sess.ImportRSAPrivateKey(label, id, priv); err != nil {
		return err
	}

	// Same headline + next-step block as runPKCS11Generate. ui.Success
	// double-formats (Sprintf then Info re-parses), so the user-controlled
	// token/label are "%"->"%%" escaped; idHex is hex-only and the bit length an
	// int, so both are safe unescaped.
	ui.Success("Imported RSA-%d key  label=%s  id=%s  onto token %s",
		priv.N.BitLen(),
		strings.ReplaceAll(label, "%", "%%"),
		idHex,
		strings.ReplaceAll(token, "%", "%%"))

	// Point the user at how to adopt this exact key as the machine identity.
	// ui.Info is single-pass Printf (format+args), so module and the "%"-bearing
	// pkcs11 URI survive literally as %s arguments with no escaping.
	uri := fmt.Sprintf("pkcs11:token=%s;id=%s;type=private",
		pctEncodePKCS11Attr(token), pctEncodeID(id))
	ui.Info("Use this key as this machine's identity:")
	ui.Info("  nvolt init --pkcs11 --pkcs11-module %s --pkcs11-uri '%s'", module, uri)

	ui.Verbose("  Bits: %d", priv.N.BitLen())

	return nil
}

func init() {
	pkcs11Cmd.AddCommand(pkcs11ListCmd)
	pkcs11ListCmd.Flags().StringVar(&pkcs11Module, "pkcs11-module", "", "Path to PKCS#11 module (.so); autodetected if omitted")

	pkcs11Cmd.AddCommand(pkcs11GenerateCmd)
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenModule, "pkcs11-module", "", "Path to PKCS#11 module (.so); autodetected if omitted")
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenToken, "token", "", "Token label to generate the key on (required)")
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenLabel, "label", "nvolt", "CKA_LABEL for the new key")
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenID, "id", "", "CKA_ID for the new key, hex (e.g. 03); auto-assigned (next free id) if omitted")
	pkcs11GenerateCmd.Flags().IntVar(&pkcs11GenBits, "bits", 2048, "RSA modulus size in bits")
	pkcs11GenerateCmd.Flags().StringVar(&pkcs11GenPinMode, "pkcs11-pin-mode", "prompt", "How to obtain the PIN: prompt, env, or none")
	_ = pkcs11GenerateCmd.MarkFlagRequired("token")

	pkcs11Cmd.AddCommand(pkcs11ImportCmd)
	pkcs11ImportCmd.Flags().StringVar(&pkcs11ImportModule, "pkcs11-module", "", "Path to PKCS#11 module (.so); autodetected if omitted")
	pkcs11ImportCmd.Flags().StringVar(&pkcs11ImportToken, "token", "", "Token label to import the key onto (required)")
	pkcs11ImportCmd.Flags().StringVar(&pkcs11ImportLabel, "label", "nvolt", "CKA_LABEL for the imported key")
	pkcs11ImportCmd.Flags().StringVar(&pkcs11ImportID, "id", "", "CKA_ID for the imported key, hex (e.g. 03); auto-assigned (next free id) if omitted")
	pkcs11ImportCmd.Flags().StringVar(&pkcs11ImportFile, "privkey", "", "Path to the RSA private key PEM to import (required)")
	pkcs11ImportCmd.Flags().StringVar(&pkcs11ImportPinMode, "pkcs11-pin-mode", "prompt", "How to obtain the PIN: prompt, env, or none")
	_ = pkcs11ImportCmd.MarkFlagRequired("token")
	_ = pkcs11ImportCmd.MarkFlagRequired("privkey")

	rootCmd.AddCommand(pkcs11Cmd)
}
