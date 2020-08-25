package phe

import (
	"github.com/stretchr/testify/assert"
	"math/rand"
	"runtime"
	"testing"
)

func TestBasicOperationPaillier(t *testing.T) {
	assert := assert.New(t)
	p, s := GenNewKeysPaillier(2048)
	assert.Equal(uint64(2), s.Decrypt(p.EncryptUint64(2)).Uint64())
	assert.Equal(uint64(6), s.Decrypt(p.Mul(p.EncryptUint64(2), 3)).Uint64())
	assert.Equal(uint64(69), s.Decrypt(p.Add(p.EncryptUint64(13), p.EncryptUint64(69-13))).Uint64())
}

func TestBasicOperationBenaloh(t *testing.T) {
	assert := assert.New(t)
	p, s := GenNewKeysBenaloh(1000000000, 2048)
	assert.Equal(uint64(2), s.Decrypt(p.EncryptUint64(2)).Uint64())
	assert.Equal(uint64(6), s.Decrypt(p.Mul(p.EncryptUint64(2), 3)).Uint64())
	assert.Equal(uint64(69), s.Decrypt(p.Add(p.EncryptUint64(13), p.EncryptUint64(69-13))).Uint64())
}

func TestVectorPaillier(t *testing.T) {
	const N = 256
	maxProcs := uint64(runtime.GOMAXPROCS(-1))
	assert := assert.New(t)
	rnd := rand.New(rand.NewSource(69))
	p, s := GenNewKeysPaillier(512)
	a := make([]uint64, N, N)
	b := make([]uint64, N, N)
	for i := 0; i < N; i++ {
		a[i] = rnd.Uint64() >> 2
		b[i] = rnd.Uint64() >> 2
	}
	ea := EncryptVectorUint64Parallel(p, a, maxProcs)
	eb := EncryptVectorUint64Parallel(p, b, maxProcs)
	ec := make([]*Ciphertext, N, N)
	for i := 0; i < N; i++ {
		ec[i] = p.Add(ea[i], eb[i])
	}
	c := DecryptVectorParallel(s, ec, maxProcs)
	for i := 0; i < N; i++ {
		assert.Equal(a[i]+b[i], c[i].Uint64())
	}
}

func TestVectorBenaloh(t *testing.T) {
	const N = 64
	maxProcs := uint64(runtime.GOMAXPROCS(-1))
	assert := assert.New(t)
	rnd := rand.New(rand.NewSource(69))
	p, s := GenNewKeysBenaloh(1<<32, 512)
	a := make([]uint64, N, N)
	b := make([]uint64, N, N)
	for i := 0; i < N; i++ {
		a[i] = rnd.Uint64() >> 34
		b[i] = rnd.Uint64() >> 34
	}
	ea := EncryptVectorUint64Parallel(p, a, maxProcs)
	eb := EncryptVectorUint64Parallel(p, b, maxProcs)
	ec := make([]*Ciphertext, N, N)
	for i := 0; i < N; i++ {
		ec[i] = p.Add(ea[i], eb[i])
	}
	c := DecryptVectorParallel(s, ec, maxProcs)
	for i := 0; i < N; i++ {
		assert.Equal(a[i]+b[i], c[i].Uint64())
	}
}
