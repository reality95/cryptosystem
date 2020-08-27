package phe

import (
	cRand "crypto/rand"
	"math/big"
	mRand "math/rand"
)

// PublicPaillier represents the public key in the Paillier cryptosystem
type PublicPaillier struct {
	n    *big.Int
	n2   *big.Int
	g    *big.Int
	gInv *big.Int
	r    *mRand.Rand
}

// SecretPaillier represents the secret key in the Paillier crypstosystem
type SecretPaillier struct {
	n      *big.Int
	n2     *big.Int
	lambda *big.Int
	phi    *big.Int
	mu     *big.Int
}

// CopyPublicPaillier to PublicPaillier
func CopyPublicPaillier(p PublicPaillier) PublicPaillier {
	return PublicPaillier{
		n:    copyInt(p.n),
		n2:   copyInt(p.n2),
		g:    copyInt(p.g),
		gInv: copyInt(p.gInv),
		r:    mRand.New(mRand.NewSource(p.r.Int63())),
	}
}

// CopySecretPaillier to SecretPaillier
func CopySecretPaillier(s SecretPaillier) SecretPaillier {
	return SecretPaillier{
		n:      copyInt(s.n),
		n2:     copyInt(s.n2),
		lambda: copyInt(s.lambda),
		phi:    copyInt(s.phi),
		mu:     copyInt(s.mu),
	}
}

// Copy the public key to an interface
func (p PublicPaillier) Copy() PublicKey {
	return CopyPublicPaillier(p)
}

// Copy the secret key to an interface
func (s SecretPaillier) Copy() SecretKey {
	return CopySecretPaillier(s)
}

// L function takes as argument a ciphertext x and returns (x - 1) / n
func (p PublicPaillier) L(x *big.Int) *big.Int {
	return divNew(subNew(x, oneInt), p.n)
}

// L function takes as argument a ciphertext x and returns (x - 1) / n
func (s SecretPaillier) L(x *big.Int) *big.Int {
	return divNew(subNew(x, oneInt), s.n)
}

func (p PublicPaillier) randInt() (ans *big.Int) {
	ans, _ = cRand.Int(p.r, p.n)
	return
}

// Decrypt decrypts a ciphertext
// using the formula L(c ** lambda mod (n ** 2)) * mu mod n
func (s SecretPaillier) Decrypt(c *Ciphertext) *big.Int {
	return bigMod(mulNew(s.L(powMod(c.num, s.lambda, s.n2)), s.mu), s.n)
}

// MulUint64 multiplies one ciphertext with a uint64 plaintext
func (p PublicPaillier) MulUint64(a *Ciphertext, b uint64) *Ciphertext {
	return &Ciphertext{num: powModUint64(a.num, b, p.n2)}
}

// MulInt64 multiplies one ciphertext with a int64 plaintext
func (p PublicPaillier) MulInt64(a *Ciphertext, b int64) *Ciphertext {
	return p.MulInt(a, nIntSetInt64(b))
}

// MulInt multiplies one ciphertext with a plaintext of arbitrary size
func (p PublicPaillier) MulInt(a *Ciphertext, b *big.Int) *Ciphertext {
	if a.num.Sign() < 0 {
		return &Ciphertext{num: powMod(invMod(a.num, p.n2), nInt().Abs(b), p.n2)}
	}
	return &Ciphertext{num: powMod(a.num, b, p.n2)}
}

// Add adds two ciphertexts
//
// In Paillier cryptosystem addition is the same as multiplication
// over ciphertexts
func (p PublicPaillier) Add(a, b *Ciphertext) *Ciphertext {
	return &Ciphertext{num: bigMod(mulNew(a.num, b.num), p.n2)}
}

// EncryptUint64 encrypt a single uint64 integer
// using the formula (g ** m) * (r ** n) mod (n ** 2)
// where r is a chosen randomly
func (p PublicPaillier) EncryptUint64(m uint64) *Ciphertext {
	gm := powModUint64(p.g, m, p.n2)
	rn := powMod(p.randInt(), p.n, p.n2)
	return &Ciphertext{num: bigMod(mulNew(gm, rn), p.n2)}
}

// EncryptInt encrypts a single integer of arbitrary size
func (p PublicPaillier) EncryptInt(m *big.Int) *Ciphertext {
	var gm *big.Int
	if m.Sign() >= 0 {
		gm = powMod(p.g, m, p.n2)
	} else {
		gm = powMod(p.gInv, nInt().Abs(m), p.n2)
	}
	rn := powMod(p.randInt(), p.n, p.n2)
	return &Ciphertext{num: bigMod(mulNew(gm, rn), p.n2)}
}

// EncryptInt64 encrypts a single int64 integer
func (p PublicPaillier) EncryptInt64(m int64) *Ciphertext {
	return p.EncryptInt(nIntSetInt64(m))
}
