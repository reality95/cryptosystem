package phe

import (
	"math/big"
)

var oneInt = nIntSetUint64(1)
var zeroInt = nIntSetUint64(0)

func bigMod(a, mod *big.Int) *big.Int {
	return a.Mod(a, mod)
}

func copyInt(x *big.Int) *big.Int {
    return nInt().Set(x)
}

func copyIntSlice(s []*big.Int) (ans []*big.Int) {
    N := len(s)
    ans = make([]*big.Int, N, N)
    for idx, num := range s {
        ans[idx] = copyInt(num)
    }
    return
}

func copyRootPowerSlice(s []rootPower) (ans []rootPower) {
    N := len(s)
    ans = make([]rootPower, N, N)
    for idx, rPow := range s {
        ans[idx] = rootPower {
            power : rPow.power,
            num : copyInt(rPow.num),
        }
    }
    return
}

func nInt() *big.Int {
	return new(big.Int)
}

func nIntSetInt64(x int64) *big.Int {
	return big.NewInt(x)
}

func nIntSetUint64(x uint64) *big.Int {
	return nInt().SetUint64(x)
}

func mul(a, b *big.Int) {
	a.Mul(a, b)
}

func mulNew(a, b *big.Int) *big.Int {
	return nInt().Mul(a, b)
}

func add(a, b *big.Int) {
	a.Add(a, b)
}

func addNew(a, b *big.Int) *big.Int {
	return nInt().Add(a, b)
}

func sub(a, b *big.Int) {
	a.Sub(a, b)
}

func subNew(a, b *big.Int) *big.Int {
	return nInt().Sub(a, b)
}

func div(a, b *big.Int) {
	a.Div(a, b)
}

func divNew(a, b *big.Int) *big.Int {
	return nInt().Div(a, b)
}

func invMod(a, b *big.Int) *big.Int {
	return nInt().ModInverse(a, b)
}

func powMod(a, b, mod *big.Int) (ans *big.Int) {
	ans = nIntSetUint64(1)
	c := nIntSetUint64(1)
	mul(c, a)
	bytes := b.Bytes()
	rBytes := make([]byte, len(bytes), len(bytes))
	for i, bt := range bytes {
		rBytes[len(bytes)-i-1] = bt
	}
	for _, bt := range rBytes {
		for i := 0; i < 8; i++ {
			if ((bt >> i) & 1) == 1 {
				mul(ans, c)
				bigMod(ans, mod)
			}
			mul(c, c)
			bigMod(c, mod)
		}
	}
	return
}

func powModUint64(a *big.Int, b uint64, mod *big.Int) *big.Int {
	ans := nIntSetUint64(1)
	c := nIntSetUint64(1)
	mul(c, a)
	// The number of iterations should be fixed to combat timing attacks
	for p := 0; p < 64; p++ {
		if (b & 1) == 1 {
			mul(ans, c)
			bigMod(ans, mod)
		}
		mul(c, c)
		bigMod(c, mod)
		b >>= 1
	}
	return ans
}
