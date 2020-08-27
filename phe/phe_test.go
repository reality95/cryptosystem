package phe

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"math/rand"
	"runtime"
	"testing"
)

var rnd = rand.New(rand.NewSource(69))

func getBasicOperationSubtest(s SecretKey, p PublicKey) func(*testing.T) {
	return func(t *testing.T) {
		assert.Equal(t, uint64(2), s.Decrypt(p.EncryptUint64(2)).Uint64())
		assert.Equal(t, uint64(6), s.Decrypt(p.MulUint64(p.EncryptUint64(2), 3)).Uint64())
		assert.Equal(t, uint64(69), s.Decrypt(p.Add(p.EncryptUint64(13), p.EncryptUint64(69-13))).Uint64())
		assert.Equal(t, int64(69-13), s.Decrypt(p.Add(p.EncryptInt64(-13), p.EncryptInt64(69))).Int64())
	}
}

func TestBasicOperation(t *testing.T) {
	p1, s1 := GenNewKeysPaillier(2048)
	p2, s2 := GenNewKeysBenaloh(1000000000, 2048)
	t.Run("Paillier", getBasicOperationSubtest(s1, p1))
	t.Run("Benaloh", getBasicOperationSubtest(s2, p2))
	modBenaloh := p2.GetPlaintextMod()
	assert.Equal(t, int64(modBenaloh-69), s2.Decrypt(p2.EncryptInt64(-69)).Int64())
}

func TestPlaintextModuloBenaloh(t *testing.T) {
	assert := assert.New(t)
	p, s := GenNewKeysBenaloh(1000000000, 2048)
	mod := int64(p.GetPlaintextMod())
	xCipher := p.EncryptUint64(0)
	xPlain := int64(0)
	for op := 0; op < 256; op++ {
		if (rnd.Uint64() & 1) == 1 {
			// perform x = x + y
			y := rnd.Int63n(mod)
			xPlain = (xPlain + y) % mod
			xCipher = p.Add(xCipher, p.EncryptInt64(y))
		} else {
			// perform x = x * y where 1 <= y < mod
			y := rnd.Int63n(mod-1) + 1
			xPlain = (xPlain * y) % mod
			xCipher = p.MulInt64(xCipher, y)
		}
		assert.Equal(xPlain, s.Decrypt(xCipher).Int64())
	}
}

func getCiphertextModuloSubtest(s SecretKey, p PublicKey, mod *big.Int) func(*testing.T) {
	return func(t *testing.T) {
		x := p.EncryptUint64(0)
		for op := 0; op < 256; op++ {
			if (rnd.Uint64() & 1) == 1 {
				// Perform x = x + y
				y := rnd.Int63()
				x = p.Add(x, p.EncryptInt64(y))
			} else {
				// Perform x = x * y where 1 <= y < mod
				y := rnd.Int63()
				x = p.MulInt64(x, y)
			}
			assert.Condition(t, func() bool { return x.num.Cmp(mod) < 0 })
		}
	}
}

func TestCiphertextModulo(t *testing.T) {
	p1, s1 := GenNewKeysPaillier(2048)
	p2, s2 := GenNewKeysBenaloh(1000000000, 2048)
	t.Run("Paillier", getCiphertextModuloSubtest(s1, p1, p1.n2))
	t.Run("Benaloh", getCiphertextModuloSubtest(s2, p2, p2.n))
}

func getVectorSubtest(s SecretKey, p PublicKey, a, b []uint64, N int) func(*testing.T) {
	return func(t *testing.T) {
		maxProcs := uint64(runtime.GOMAXPROCS(-1))
		ea := EncryptVectorUint64Parallel(p, a, maxProcs)
		eb := EncryptVectorUint64Parallel(p, b, maxProcs)
		ec := make([]*Ciphertext, N, N)
		for i := 0; i < N; i++ {
			ec[i] = p.Add(ea[i], eb[i])
		}
		c := DecryptVectorParallel(s, ec, maxProcs)
		for i := 0; i < N; i++ {
			assert.Equal(t, a[i]+b[i], c[i].Uint64())
		}
	}
}

func TestVector(t *testing.T) {
	const N1 = 256
	const N2 = 64
	p1, s1 := GenNewKeysPaillier(512)
	p2, s2 := GenNewKeysBenaloh(1<<32, 512)
	a1 := make([]uint64, N1, N1)
	b1 := make([]uint64, N1, N1)
	a2 := make([]uint64, N2, N2)
	b2 := make([]uint64, N2, N2)
	for i := 0; i < N1; i++ {
		a1[i] = rnd.Uint64() >> 2
		b1[i] = rnd.Uint64() >> 2
	}
	for i := 0; i < N2; i++ {
		a2[i] = rnd.Uint64() >> 34
		b2[i] = rnd.Uint64() >> 34
	}
	t.Run("Paillier", getVectorSubtest(s1, p1, a1, b1, N1))
	t.Run("Benaloh", getVectorSubtest(s2, p2, a2, b2, N2))
}
