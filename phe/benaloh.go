package phe

import (
	cRand "crypto/rand"
	mRand "math/rand"
	"math/big"
	"sort"
)

type rootPower struct {
	power uint64
	num   *big.Int
}

// PublicBenaloh represents the public key in the Paillier cryptosystem
type PublicBenaloh struct {
	y    *big.Int
	n    *big.Int
	rBig *big.Int
	r    uint64
	rn   *mRand.Rand
}

// SecretBenaloh represents the secret key in the Paillier crypstosystem
type SecretBenaloh struct {
	phi         *big.Int
	n           *big.Int
	rBig        *big.Int
	r           uint64
	sqrtR       uint64
	phiOverR    *big.Int
	xInvPowers  []*big.Int
	xSqrtPowers []rootPower
}

// CopyPublicBenaloh to PublicBenaloh
func CopyPublicBenaloh(p PublicBenaloh) PublicBenaloh {
    return PublicBenaloh {
        y : copyInt(p.y),
        n : copyInt(p.n),
        rBig : copyInt(p.rBig),
        r : p.r,
        rn : mRand.New(mRand.NewSource(p.rn.Int63())),
    }
}

// CopySecretBenaloh to SecretBenaloh
func CopySecretBenaloh(s SecretBenaloh) SecretBenaloh {
    return SecretBenaloh {
        phi : copyInt(s.phi),
        n : copyInt(s.n),
        rBig : copyInt(s.rBig),
        r : s.r,
        sqrtR : s.sqrtR,
        phiOverR : copyInt(s.phiOverR),
        xInvPowers : copyIntSlice(s.xInvPowers),
        xSqrtPowers : copyRootPowerSlice(s.xSqrtPowers),
    }
}

// Copy the public key to an interface
func (p PublicBenaloh) Copy() PublicKey {
    return CopyPublicBenaloh(p)
}

// Copy the secret key to an interface
func (s SecretBenaloh) Copy() SecretKey {
    return CopySecretBenaloh(s)
}

// Mul multiplies one ciphertext with a plaintext
//
// In Benaloh cryptosystem multiplication of a ciphertext `a`
// with a plaintext `b` is the same as take `a` to the power of `b`
func (p PublicBenaloh) Mul(a *Ciphertext, b uint64) *Ciphertext {
	return &Ciphertext{num: powModUint64(a.num, b, p.n)}
}

// GetPlaintextMod returns the mod over which all
// plaintext operations are done
//
// In Benaloh cryptosystem it correspond to r
func (p PublicBenaloh) GetPlaintextMod() uint64 {
	return p.r
}

func (p PublicBenaloh) randInt() (ans *big.Int) {
    ans, _ = cRand.Int(p.rn, p.n)
	return
}

// Add adds two ciphertexts
//
// In Benaloh cryptosystem addition is the same as multiplication
// over ciphertexts
func (p PublicBenaloh) Add(a, b *Ciphertext) *Ciphertext {
	return &Ciphertext{num: bigMod(mulNew(a.num, b.num), p.n)}
}

// EncryptUint64 encrypt a single uint64 message
// using the formula ((y ** m) * (u ** r)) mod n
// where u is a chosen randomly
func (p PublicBenaloh) EncryptUint64(m uint64) *Ciphertext {
    ym := powMod(p.y, nIntSetUint64(m), p.n)
    ur := powModUint64(p.randInt(), p.r, p.n)
	return &Ciphertext{num: bigMod(mulNew(ym, ur), p.n)}
}

// IsZero quickly checks if the plaintext is 0 or not 
// It's preffered when r is big enough
func (s SecretBenaloh) IsZero(c *Ciphertext) bool {
    return powMod(c.num, s.phiOverR, s.n).Cmp(oneInt) == 0
}

// Decrypt decrypts a ciphertext by finding an m
// such that x ** m = c ** (phi / r) mod n
func (s SecretBenaloh) Decrypt(c *Ciphertext) *big.Int {
    // a = c ** (phi / r) mod n
	a := powMod(c.num, s.phiOverR, s.n)
	for power, num := range s.xInvPowers {
        // sqrtPower = a * x ** (-power0)
		sqrtPower := bigMod(mulNew(a, num), s.n)
        // if we find power1 such that 
        // sqrtPower == x ** (power1 * sqrtR)
        // then the answer is power1 * sqrtR + power0
		sqrtPowerIndex := sort.Search(len(s.xSqrtPowers), func(idx int) bool {
			return s.xSqrtPowers[idx].num.Cmp(sqrtPower) >= 0
		})
		if sqrtPowerIndex < len(s.xSqrtPowers) {
			if s.xSqrtPowers[sqrtPowerIndex].num.Cmp(sqrtPower) == 0 {
                // take mod r since it might overflow
				return nIntSetUint64((s.xSqrtPowers[sqrtPowerIndex].power + uint64(power)) % s.r)
			}
		}
	}
	panic("Unable to Decrypt a Benaloh Ciphertext, was the ciphertext correct?")
}
