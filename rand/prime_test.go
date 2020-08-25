package rand

import (
	cRand "crypto/rand"
	"github.com/stretchr/testify/assert"
	"math/big"
	mRand "math/rand"
	"testing"
)

func TestRandomPSIRand(t *testing.T) {
	assert := assert.New(t)
	rnd := mRand.New(mRand.NewSource(69))
	r := uint64(1000000007)
	rBig := new(big.Int).SetUint64(r)
	p, err := Prime(rnd, 1024, r)
	assert.Equal(err, nil, "Expected no error for big bits")
	bigMod := new(big.Int).Mod(p, rBig)
	assert.Equal(bigMod.Uint64(), uint64(1), "Expected the prime to have residue 1 when divided by r")
}

func BenchmarkRandomCryptoRand(b *testing.B) {
	rnd := mRand.New(mRand.NewSource(669))
	r := uint64(667)
	rBig := new(big.Int).SetUint64(r)
	var p *big.Int
	var err error
	for {
		p, err = cRand.Prime(rnd, 1024)
		if err == nil && new(big.Int).Mod(p, rBig).Cmp(oneInt) == 0 {
			break
		}
	}
}
