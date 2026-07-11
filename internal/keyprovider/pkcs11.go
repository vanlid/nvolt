package keyprovider

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	nvcrypto "github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/pkcs11"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/iluxav/nvolt/pkg/types"
)

// errUnwrap is the SINGLE opaque error returned for every runtime unwrap
// failure. Distinguishing OAEP padding failures from other decrypt failures
// would hand an attacker a padding oracle (Task 3 security requirement), so all
// failure paths inside Decrypt collapse to this one value.
var errUnwrap = errors.New("pkcs11: unwrap failed")

// errPromptPINUnimplemented marks the pin_mode="prompt" hook that Task 8 will
// replace with an interactive TTY prompt. It is intentionally a distinct,
// pre-cryptographic configuration error (it fires before any ciphertext is
// presented to the token), so it is safe to surface without opacity concerns.
var errPromptPINUnimplemented = errors.New("prompt PIN entry wired in Task 8")

// Enroll validates that a PKCS#11 token can serve as this machine's key backend
// and pins the OAEP unwrap mode it actually supports.
//
// It parses the RFC7512 pkcs11: URI for token/id, opens a session, logs in with
// the supplied PIN, and runs these checks — failing at enroll time rather than
// at first pull:
//  1. an RSA private key with the requested id exists on the token;
//  2. its public key reads back and is at least 2048 bits;
//  3. an OAEP-SHA256 self-test round-trips a freshly wrapped AES key, selecting
//     oaep_mode "native" (token performs OAEP-SHA256) or "raw" (token does raw
//     RSA and nvolt strips OAEP padding in software).
//
// On success it returns the KeySource to persist plus the card's public key.
func Enroll(module, uri, pinMode string, pin func() (string, error)) (types.KeySource, *rsa.PublicKey, error) {
	token, id, err := parsePKCS11URI(uri)
	if err != nil {
		return types.KeySource{}, nil, err
	}

	m, err := pkcs11.Open(module)
	if err != nil {
		return types.KeySource{}, nil, err
	}
	defer m.Close()

	sess, err := m.OpenSession(token)
	if err != nil {
		return types.KeySource{}, nil, err
	}
	defer sess.Close()

	p, err := pin()
	if err != nil {
		return types.KeySource{}, nil, fmt.Errorf("obtain PIN: %w", err)
	}
	if err := sess.Login(p); err != nil {
		return types.KeySource{}, nil, err
	}

	priv, err := sess.FindRSAPrivateKey(id)
	if err != nil {
		return types.KeySource{}, nil, err
	}

	pub, err := sess.RSAPublicKey(priv)
	if err != nil {
		return types.KeySource{}, nil, fmt.Errorf("read RSA public key from token: %w", err)
	}
	if pub.N.BitLen() < 2048 {
		return types.KeySource{}, nil, fmt.Errorf("token RSA key is %d bits; minimum 2048 required", pub.N.BitLen())
	}

	mode, err := selfTestOAEP(sess, priv, pub)
	if err != nil {
		return types.KeySource{}, nil, err
	}

	src := types.KeySource{
		Source:   "pkcs11",
		Module:   module,
		URI:      uri,
		PinMode:  pinMode,
		OAEPMode: mode,
	}
	return src, pub, nil
}

// selfTestOAEP wraps a random AES key to pub and unwraps it on the token to
// determine which mechanism the token can perform, returning "native" or "raw".
func selfTestOAEP(sess *pkcs11.Session, priv pkcs11.Object, pub *rsa.PublicKey) (string, error) {
	aes, err := nvcrypto.GenerateAESKey()
	if err != nil {
		return "", fmt.Errorf("self-test: generate AES key: %w", err)
	}
	ct, err := nvcrypto.WrapKey(pub, aes)
	if err != nil {
		return "", fmt.Errorf("self-test: wrap key: %w", err)
	}

	// Prefer native OAEP-SHA256.
	if got, err := sess.DecryptOAEPSHA256(priv, ct); err == nil && bytes.Equal(got, aes) {
		return "native", nil
	}

	// Fall back to raw RSA + software OAEP unpad. Reached when the token lacks
	// native OAEP-SHA256 (ErrMechanismUnsupported) or returned a mismatch.
	if raw, err := sess.DecryptRawRSA(priv, ct); err == nil {
		k := (pub.N.BitLen() + 7) / 8
		if got, err := nvcrypto.UnpadOAEPSHA256(raw, k); err == nil && bytes.Equal(got, aes) {
			return "raw", nil
		}
	}

	return "", errors.New("token cannot perform OAEP-SHA256 unwrap")
}

// parsePKCS11URI is a minimal RFC7512 parser extracting the token label and the
// percent-decoded key id. It intentionally supports only the attributes nvolt
// needs (token, id) and adds no dependency.
func parsePKCS11URI(uri string) (token string, id []byte, err error) {
	rest, ok := strings.CutPrefix(uri, "pkcs11:")
	if !ok {
		return "", nil, fmt.Errorf("not a pkcs11 URI: %q", uri)
	}
	for _, part := range strings.Split(rest, ";") {
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch key {
		case "token":
			token, err = url.PathUnescape(val)
			if err != nil {
				return "", nil, fmt.Errorf("pkcs11 URI token=: %w", err)
			}
		case "id":
			dec, derr := url.PathUnescape(val)
			if derr != nil {
				return "", nil, fmt.Errorf("pkcs11 URI id=: %w", derr)
			}
			id = []byte(dec)
		}
	}
	if token == "" {
		return "", nil, fmt.Errorf("pkcs11 URI missing token=: %q", uri)
	}
	if len(id) == 0 {
		return "", nil, fmt.Errorf("pkcs11 URI missing id=: %q", uri)
	}
	return token, id, nil
}

// pkcs11Decrypter is a crypto.Decrypter backed by an open, logged-in PKCS#11
// session. Public() returns the machine's stored public key; Decrypt() unwraps
// on the token per the enrolled oaep_mode.
type pkcs11Decrypter struct {
	src  types.KeySource
	pub  *rsa.PublicKey
	sess *pkcs11.Session
	priv pkcs11.Object
}

// Public returns the machine's stored public key.
func (d *pkcs11Decrypter) Public() crypto.PublicKey { return d.pub }

// Decrypt unwraps a ciphertext on the token. All failures return the single
// opaque errUnwrap so no padding-oracle signal leaks.
func (d *pkcs11Decrypter) Decrypt(_ io.Reader, wrapped []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	switch d.src.OAEPMode {
	case "native":
		out, err := d.sess.DecryptOAEPSHA256(d.priv, wrapped)
		if err != nil {
			return nil, errUnwrap
		}
		return out, nil
	case "raw":
		raw, err := d.sess.DecryptRawRSA(d.priv, wrapped)
		if err != nil {
			return nil, errUnwrap
		}
		out, err := nvcrypto.UnpadOAEPSHA256(raw, (d.pub.N.BitLen()+7)/8)
		if err != nil {
			return nil, errUnwrap
		}
		return out, nil
	default:
		return nil, errUnwrap
	}
}

// loadPKCS11Decrypter opens the token, logs in, and returns a crypto.Decrypter
// bound to the enrolled key plus a close func that finalizes the session and
// module. The public key comes from the machine's stored PEM (not the token),
// matching the software backend.
func loadPKCS11Decrypter(src types.KeySource) (crypto.Decrypter, func() error, error) {
	pub, err := machinePublicKey()
	if err != nil {
		return nil, nil, err
	}
	token, id, err := parsePKCS11URI(src.URI)
	if err != nil {
		return nil, nil, err
	}
	pin, err := resolvePIN(src.PinMode)
	if err != nil {
		return nil, nil, err
	}

	m, err := pkcs11.Open(src.Module)
	if err != nil {
		return nil, nil, err
	}
	sess, err := m.OpenSession(token)
	if err != nil {
		_ = m.Close()
		return nil, nil, err
	}
	if pin != "" {
		if err := sess.Login(pin); err != nil {
			_ = sess.Close()
			_ = m.Close()
			return nil, nil, err
		}
	}
	priv, err := sess.FindRSAPrivateKey(id)
	if err != nil {
		_ = sess.Close()
		_ = m.Close()
		return nil, nil, err
	}

	dec := &pkcs11Decrypter{src: src, pub: pub, sess: sess, priv: priv}
	closeFn := func() error {
		_ = sess.Close()
		return m.Close()
	}
	return dec, closeFn, nil
}

// resolvePIN returns the PIN for the given pin_mode. "env" reads
// NVOLT_PKCS11_PIN; "prompt" is the Task 8 hook (returns
// errPromptPINUnimplemented until a TTY prompt is wired); "none"/"" means the
// token is used without a login.
func resolvePIN(mode string) (string, error) {
	switch mode {
	case "env":
		pin := os.Getenv("NVOLT_PKCS11_PIN")
		if pin == "" {
			return "", errors.New("pin_mode=env but NVOLT_PKCS11_PIN is not set")
		}
		return pin, nil
	case "prompt":
		// TASK 8: replace with an interactive TTY prompt for the PIN.
		return "", errPromptPINUnimplemented
	case "none", "":
		return "", nil
	default:
		return "", fmt.Errorf("unknown pin_mode %q", mode)
	}
}

// machinePublicKey loads this machine's stored public key from machine-info.json.
func machinePublicKey() (*rsa.PublicKey, error) {
	mi, err := vault.LoadMachineInfo()
	if err != nil {
		return nil, err
	}
	if mi.PublicKey == "" {
		return nil, errors.New("machine info has no public key")
	}
	return nvcrypto.DecodePublicKeyPEM([]byte(mi.PublicKey))
}
