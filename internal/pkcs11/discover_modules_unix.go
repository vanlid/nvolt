//go:build pkcs11 && !windows

package pkcs11

import (
	"os"
	"path/filepath"
)

// p11KitProxyCandidates lists the common install paths of the p11-kit proxy
// module. When present, the proxy transparently exposes every token that any
// p11-kit-registered provider knows about, so it is the single best default:
// DetectModules surfaces it first.
var p11KitProxyCandidates = []string{
	"/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so",
	"/usr/lib/p11-kit-proxy.so",
	"/usr/lib64/p11-kit-proxy.so",
	"/opt/homebrew/lib/p11-kit-proxy.so",
	"/usr/local/lib/p11-kit-proxy.so",
}

// DetectModules discovers PKCS#11 provider libraries on Unix-like systems and
// returns them deduped by cleaned absolute path. A p11-kit proxy (if any) is
// listed first as it aggregates every registered token; the common per-OS
// install paths (OpenSC, YubiKey ykcs11, p11-kit-client) follow, labeled by
// basename. Any common-path entry whose path resolves to the proxy is skipped.
func DetectModules() []DiscoveredModule {
	mods := detectModulesUnix(p11KitProxyCandidates, candidatesForOS())
	return appendEmbeddedOption(mods, embeddedModuleAvailable)
}

// detectModulesUnix is the injectable core of DetectModules: it probes the
// given proxy and common-path candidate lists so tests can drive it with
// synthetic temp files instead of the real per-OS globals.
func detectModulesUnix(proxyCandidates, pathCandidates []string) []DiscoveredModule {
	var mods []DiscoveredModule
	seen := make(map[string]bool)

	// A single p11-kit proxy, if installed, comes first.
	for _, path := range proxyCandidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		key := cleanModuleKey(path)
		if seen[key] {
			continue
		}
		seen[key] = true
		mods = append(mods, DiscoveredModule{
			Path:   path,
			Name:   "p11-kit",
			Label:  "p11-kit (all registered tokens)",
			Source: "p11-kit",
		})
		break
	}

	// Then each existing common-path provider, deduped against the proxy.
	for _, path := range pathCandidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		key := cleanModuleKey(path)
		if seen[key] {
			continue
		}
		seen[key] = true
		mods = append(mods, DiscoveredModule{
			Path:   path,
			Name:   friendlyModuleName(path),
			Label:  filepath.Base(path),
			Source: "path",
		})
	}

	return mods
}
