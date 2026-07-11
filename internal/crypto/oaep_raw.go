package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
)

// UnpadOAEPSHA256 removes OAEP (SHA-256, MGF1-SHA256, empty label) padding from a
// raw RSA decryption result `em` of length k (the modulus size in bytes).
func UnpadOAEPSHA256(em []byte, k int) ([]byte, error) {
	h := sha256.New()
	hLen := h.Size()
	if k < 2*hLen+2 || len(em) != k {
		return nil, errors.New("oaep: bad length")
	}
	h.Write(nil)
	lHash := h.Sum(nil)

	y := em[0]
	maskedSeed := em[1 : 1+hLen]
	maskedDB := em[1+hLen:]
	seed := xorMGF1(maskedSeed, maskedDB, sha256.New)
	db := xorMGF1(maskedDB, seed, sha256.New)

	lHash2 := db[:hLen]
	rest := db[hLen:]

	// Constant-time scan for the 0x01 separator that follows the zero padding.
	// All observations are folded into a single decision value with one branch,
	// so success/failure and the separator position never leak via control flow.
	lookingForIndex := 1
	index := 0
	invalid := 0
	for i := 0; i < len(rest); i++ {
		equals0 := subtle.ConstantTimeByteEq(rest[i], 0)
		equals1 := subtle.ConstantTimeByteEq(rest[i], 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals1, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals1, 0, lookingForIndex)
		invalid = subtle.ConstantTimeSelect(lookingForIndex&^equals0, 1, invalid)
	}

	good := subtle.ConstantTimeByteEq(y, 0)
	good &= subtle.ConstantTimeCompare(lHash, lHash2)
	good &= 1 ^ invalid         // no non-zero byte before the separator
	good &= 1 ^ lookingForIndex // a separator byte was found
	if good != 1 {
		return nil, errors.New("oaep: decryption error")
	}
	return rest[index+1:], nil
}

// xorMGF1 returns a XOR (MGF1(seed) over len(target)).
func xorMGF1(target, seed []byte, newHash func() hash.Hash) []byte {
	out := make([]byte, len(target))
	mgf1XOR(out, newHash(), seed, target)
	return out
}

// mgf1XOR writes target XOR MGF1(seed) into out.
func mgf1XOR(out []byte, h hash.Hash, seed, target []byte) {
	var counter [4]byte
	var digest []byte
	done := 0
	for done < len(out) {
		h.Reset()
		h.Write(seed)
		h.Write(counter[:])
		digest = h.Sum(digest[:0])
		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] = target[done] ^ digest[i]
			done++
		}
		// increment counter
		for i := 3; i >= 0; i-- {
			counter[i]++
			if counter[i] != 0 {
				break
			}
		}
	}
}
