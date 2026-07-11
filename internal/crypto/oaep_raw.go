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
	// find 0x01 separator after zero padding
	var one, index int
	for i := 0; i < len(rest); i++ {
		if rest[i] == 1 && one == 0 {
			one, index = 1, i
		} else if rest[i] != 0 && one == 0 {
			one = -1 // nonzero before separator => invalid
		}
	}
	good := subtle.ConstantTimeByteEq(y, 0)
	good &= subtle.ConstantTimeCompare(lHash, lHash2)
	if good != 1 || one != 1 {
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
