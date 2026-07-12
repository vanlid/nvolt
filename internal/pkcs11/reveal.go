//go:build pkcs11 || tpm_static

package pkcs11

// FillHiddenKeyInfo re-reads, post-login, the RSA public half of every key in
// keys whose size the token hid during no-login discovery (Bits == 0), filling
// in Bits and Fingerprint. It opens a session on tokenLabel of module, logs in
// with pin, and for each hidden key reads the modulus/exponent that some tokens
// (notably wolfPKCS11, which exposes CKA_MODULUS/CKA_PUBLIC_EXPONENT only after
// authentication) refuse to reveal pre-login.
//
// Keys already visible pre-login (Bits != 0) are returned unchanged; a key
// still unreadable after login keeps Bits == 0 and an empty Fingerprint. The
// returned slice is always a fresh copy — the input is never mutated, and it is
// returned even on error so a caller can degrade gracefully. It is the
// post-login counterpart to the no-login discovery in ListTokensAndKeys /
// rsaKeyInfo, split out here so the login-and-re-read step is testable
// independently of the interactive PIN prompt in the CLI that drives it.
func FillHiddenKeyInfo(module, tokenLabel, pin string, keys []KeyInfo) ([]KeyInfo, error) {
	out := make([]KeyInfo, len(keys))
	copy(out, keys)

	m, err := Open(module)
	if err != nil {
		return out, err
	}
	defer func() { _ = m.Close() }()

	sess, err := m.OpenSession(tokenLabel)
	if err != nil {
		return out, err
	}
	defer func() { _ = sess.Close() }()

	if err := sess.Login(pin); err != nil {
		return out, err
	}

	for i := range out {
		if out[i].Bits != 0 {
			continue
		}
		// Post-login the private object's CKA_MODULUS becomes readable;
		// RSAPublicKeyByID still prefers the public-key object but now succeeds
		// on tokens that hid both pre-login. Best-effort per key: a key whose
		// public half still can't be read keeps its hidden display.
		pub, perr := sess.RSAPublicKeyByID(out[i].ID)
		if perr != nil {
			continue
		}
		out[i].Bits = pub.N.BitLen()
		out[i].Fingerprint = pubFingerprint(pub)
	}
	return out, nil
}
