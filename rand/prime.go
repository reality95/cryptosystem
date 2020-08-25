// The code below was adapted from crypto/rand/util.go
// to make it faster to generate a prime P such that
// P mod r = 1 for arbitrary big r
//
// Since there will not always be a prime if the `bits`
// is too small, care needs to be taken so that Prime
// functions will not loop infinitely
//

package rand

import (
        "errors"
        "io"
        "math/big"
)

const uint64Max = (1 << 64) - 1

var smallPrimes = []uint8{
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
}

var smallPrimesProduct = new(big.Int).SetUint64(16294579238595022365)

var oneInt = new(big.Int).SetUint64(1)

func Prime(rand io.Reader, bits int, r uint64) (p *big.Int, err error) {
    if bits < 2 {
		err = errors.New("crypto/rand: prime size must be at least 2-bit")
		return
	}

	b := uint(bits % 8)
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, (bits+7)/8)
	p = new(big.Int)

	bigMod := new(big.Int)

    rBig := new(big.Int).SetUint64(r)

	for {
		_, err = io.ReadFull(rand, bytes)
		if err != nil {
			return nil, err
		}

		// Clear bits in the first byte to make sure the candidate has a size <= bits.
		bytes[0] &= uint8(int(1<<b) - 1)
		// Don't let the value be too small, i.e, set the most significant two bits.
		// Setting the top two bits, rather than just the top bit,
		// means that when two of these values are multiplied together,
		// the result isn't ever one bit short.
		if b >= 2 {
			bytes[0] |= 3 << (b - 2)
		} else {
			// Here b==1, because b cannot be zero.
			bytes[0] |= 1
			if len(bytes) > 1 {
				bytes[1] |= 0x80
			}
		}
		// Make the value odd since an even number this large certainly isn't prime.
		bytes[len(bytes)-1] |= 1

		p.SetBytes(bytes)

        // If p > r then make p be equivalent to 1 mod r
        // By taking p = p - ((p - 1) mod r)
        if p.Cmp(rBig) > 0 {
            // p - 1
            bigMod.Sub(p, oneInt)
            // (p - 1) mod r
            bigMod.Mod(bigMod, rBig)
            // p - ((p - 1) mod r)
            p.Sub(p, bigMod)
        } else {
            continue
        }

		// Calculate the value mod the product of smallPrimes. If it's
		// a multiple of any of these primes we add two until it isn't.
		// The probability of overflowing is minimal and can be ignored
		// because we still perform Miller-Rabin tests on the result.
		bigMod.Mod(p, smallPrimesProduct)
		mod := bigMod.Uint64()

	NextDelta:
		for delta, deltaMax := uint64(0), (uint64Max - mod) / r; delta < 1<<20 && delta <= deltaMax; delta += 2 {
			m := mod + delta * r
			for _, prime := range smallPrimes {
				if m%uint64(prime) == 0 && (bits > 6 || m != uint64(prime)) {
					continue NextDelta
				}
			}

			if delta > 0 {
				bigMod.SetUint64(delta * r)
				p.Add(p, bigMod)
			}
			break
		}

		// There is a tiny possibility that, by adding delta, we caused
		// the number to be one bit too long. Thus we check BitLen
		// here.
		if p.ProbablyPrime(20) && p.BitLen() == bits {
			return
		}
	}
}
