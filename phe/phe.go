package phe

import (
	pRand "github.com/reality95/cryptosystem/rand"
	cRand "crypto/rand"
	"math"
	"math/big"
	mRand "math/rand"
	"sort"
	"sync"
	"time"
)

// Ciphertext is the encrypted form
// over which all operations are done
type Ciphertext struct {
	num *big.Int
}

// PublicKey for any phe cryptosystem must implement
// the following functions
type PublicKey interface {
	EncryptUint64(uint64) *Ciphertext
	EncryptInt64(int64) *Ciphertext
	EncryptInt(*big.Int) *Ciphertext
	Add(*Ciphertext, *Ciphertext) *Ciphertext
	Mul(*Ciphertext, uint64) *Ciphertext
	Copy() PublicKey
}

// SecretKey for any phe cryptosystem much implement
// the decryption
type SecretKey interface {
	Decrypt(*Ciphertext) *big.Int
	Copy() SecretKey
}

func gcd(a, b uint64) uint64 {
	if b == 0 {
		return a
	}
	return gcd(b, a%b)
}

func isPrime(r uint64) bool {
	if r == 2 || r == 3 || r == 5 {
		return true
	}

	if gcd(r, 30) != 1 {
		return false
	}

	// We need to check only for i primes
	// note that if i is prime > 5 then i must
	// be 1,5 mod 6 so there is no point in
	// looking at other residues
	for i := uint64(7); i*i <= r; i += 6 {
		if r%i == 0 {
			return false
		}

		if r%(i+4) == 0 {
			return false
		}
	}

	return true
}

// GenNewKeysBenaloh generates a public and a secret Benaloh key such that
// both primes are chosen randomly to have at most `security` bits
func GenNewKeysBenaloh(r uint64, security int) (p PublicBenaloh, s SecretBenaloh) {
	if r < 1<<30 {
		for !isPrime(r) {
			r++
		}
	} else {
		for !nIntSetUint64(r).ProbablyPrime(32) {
			r++
		}
	}

	p.rn = mRand.New(mRand.NewSource(time.Now().UTC().UnixNano()))
	p.r = r
	s.r = r
	rBig := nIntSetUint64(r)
	p.rBig = rBig
	s.rBig = rBig
	var p1, p2, p1_1, p2_1 *big.Int
	// Computing prime p1 such that (p1 - 1, r) = 1
	for {
		p1, _ = cRand.Prime(p.rn, security)
		p1_1 = subNew(p1, oneInt)
		if nInt().GCD(nil, nil, p1_1, rBig).Cmp(oneInt) == 0 {
			break
		}
	}
	// Computing prime p2 such that (p2 - 1, r) = r
	for {
		p2, _ = pRand.Prime(p.rn, security, r)
		p2_1 = subNew(p2, oneInt)
		rem := nInt().Div(p2_1, rBig)
		if nInt().GCD(nil, nil, rem, rBig).Cmp(oneInt) == 0 {
			break
		}
	}
	p.n = mulNew(p1, p2)
	s.n = p.n
	s.phi = mulNew(p1_1, p2_1)       // phi(n) = (p1 - 1)(p2 - 1)
	s.phiOverR = divNew(s.phi, rBig) // phi(n) / r
	// Generate y such that y ** (phi(n) / r) != 1 mod n
	for {
		p.y, _ = cRand.Int(p.rn, p.n)
		if p.y.Cmp(zeroInt) != 0 && powMod(p.y, s.phiOverR, p.n).Cmp(oneInt) != 0 {
			break
		}
	}

	p.yInv = invMod(p.y, p.n)

	sqrtR := uint64(math.Ceil(math.Sqrt(float64(r))))
	s.sqrtR = sqrtR

	s.xInvPowers = make([]*big.Int, sqrtR, sqrtR)
	s.xSqrtPowers = make([]rootPower, sqrtR, sqrtR)

	// x = y ** (phi(n) / r) mod n
	// x is a root of order r modulo n
	x := powMod(p.y, s.phiOverR, p.n)
	// x ** (-1) mod n
	xInv := invMod(x, p.n)
	// x ** (sqrtR) mod n
	xSqrtPower := powMod(x, nIntSetUint64(sqrtR), p.n)

	s.xInvPowers[0] = nIntSetUint64(1)
	s.xSqrtPowers[0] = rootPower{power: 0, num: nIntSetUint64(1)}

	for i := uint64(1); i < sqrtR; i++ {
		// x ** (-i) mod n
		s.xInvPowers[i] = bigMod(mulNew(xInv, s.xInvPowers[i-1]), s.n)
		// x ** (i * sqrtR) mod n
		s.xSqrtPowers[i] = rootPower{power: i * sqrtR, num: bigMod(mulNew(xSqrtPower, s.xSqrtPowers[i-1].num), s.n)}
	}

	sort.Slice(s.xSqrtPowers, func(i, j int) bool {
		return s.xSqrtPowers[i].num.Cmp(s.xSqrtPowers[j].num) < 0
	})

	return
}

// GenNewKeysPaillier generates a public and a secret Paillier key such that
// both primes are chosen randomly to have at most `security` bits
func GenNewKeysPaillier(security int) (p PublicPaillier, s SecretPaillier) {
	p.r = mRand.New(mRand.NewSource(time.Now().UTC().UnixNano()))
	p1, _ := cRand.Prime(p.r, security)
	p2, _ := cRand.Prime(p.r, security)
	p.n = mulNew(p1, p2)
	s.n = p.n
	p.n2 = mulNew(p.n, p.n) // n ** 2
	s.n2 = p.n2
	p1_1 := subNew(p1, oneInt) // (p1 - 1)
	p2_1 := subNew(p2, oneInt) // (p2 - 1)
	s.phi = mulNew(p1_1, p2_1) // (p1 - 1) * (p2 - 1)
	gcd := nInt().GCD(nil, nil, p1_1, p2_1)
	s.lambda = divNew(s.phi, gcd) // (p1 - 1) * (p2 - 1) / gcd(p1 - 1, p2 - 1)
	p.g = addNew(p.n, oneInt)     // n + 1 is a general prefference for g
	p.gInv = invMod(p.g, p.n2)
	s.mu = invMod(p.L(powMod(p.g, s.lambda, p.n2)), s.n) // mu = L(g ** lambda) ** (-1) mod n
	return
}

// EncryptVectorUint64Fast reuses random numbers r in the encryption protocol
// i.e. after picking a random r, we will take r[i] = r**(Random(0, 2^64 - 1))
// then to encrypt msgs[i], we will take ans[i] = (g ** msgs[i]) * (r[i] ** n)
//
// So if for some reason, msgs[i] for some i is found out by a third party,
// in the normal protocol, this doesn't leak any other msgs[j] for i != j,
// in this version however upon finding msgs[i] for some i, it will be possible
// to find all other msgs[j] using c * 2^64 tries.
//
// In other words, the security of the whole vector in this case is the same
// as the security for only one element in the general case
//
// This is not a part of the official protocol so use at your own risk
func EncryptVectorUint64Fast(p PublicPaillier, msgs []uint64) (ans []*Ciphertext) {
	N := len(msgs)
	ans = make([]*Ciphertext, N, N)
	rn := powMod(p.randInt(), p.n, p.n2)
	for i, msg := range msgs {
		ans[i].num = bigMod(mulNew(powModUint64(p.g, msg, p.n2), powModUint64(rn, p.r.Uint64(), p.n2)), p.n2)
	}
	return
}

// EncryptVectorUint64 encrypts a vector of uint64 messages
// performing p.Encrypt for every message in the vector
func EncryptVectorUint64(p PublicKey, msgs []uint64) (ans []*Ciphertext) {
	N := len(msgs)
	ans = make([]*Ciphertext, N, N)
	for i, msg := range msgs {
		ans[i] = p.EncryptUint64(msg)
	}
	return
}

// EncryptVectorUint64Parallel encrypts a vector of uint64 messages
// performing p.Encrypt for every message in the vector and using
// at most maxProcs go routines
func EncryptVectorUint64Parallel(p PublicKey, msgs []uint64, maxProcs uint64) (ans []*Ciphertext) {
	N := uint64(len(msgs))
	ans = make([]*Ciphertext, N, N)
	B := uint64(N+maxProcs-1) / maxProcs
	var wg sync.WaitGroup
	encryptSlice := func(msgsSlice []uint64, ansSlice []*Ciphertext, pk PublicKey) {
		defer wg.Done()
		for i, msg := range msgsSlice {
			ansSlice[i] = pk.EncryptUint64(msg)
		}
	}
	for w := uint64(0); w*B < N; w++ {
		leftSliceBound := w * B
		rightSliceBound := min(w*B+B, N)
		wg.Add(1)
		go encryptSlice(msgs[leftSliceBound:rightSliceBound], ans[leftSliceBound:rightSliceBound], p.Copy())
	}
	wg.Wait()
	return
}

// DecryptVector decrypts a vector of ciphertexts using
// s.Decrypt method on every ciphertext in the vector
func DecryptVector(s SecretKey, v []*Ciphertext) (ans []*big.Int) {
	N := len(v)
	ans = make([]*big.Int, N, N)
	for i := 0; i < N; i++ {
		ans[i] = s.Decrypt(v[i])
	}
	return
}

// DecryptVectorParallel decrypts a vector of ciphertexts using
// s.Decrypt method on every ciphertext in the vector using
// at most maxProcs go routines
func DecryptVectorParallel(s SecretKey, v []*Ciphertext, maxProcs uint64) (ans []*big.Int) {
	N := uint64(len(v))
	ans = make([]*big.Int, N, N)
	B := uint64(N+maxProcs-1) / maxProcs
	var wg sync.WaitGroup
	decryptSlice := func(vSlice []*Ciphertext, ansSlice []*big.Int, sk SecretKey) {
		defer wg.Done()
		for i, c := range vSlice {
			ansSlice[i] = sk.Decrypt(c)
		}
	}
	for w := uint64(0); w*B < N; w++ {
		leftSliceBound := w * B
		rightSliceBound := min(w*B+B, N)
		wg.Add(1)
		go decryptSlice(v[leftSliceBound:rightSliceBound], ans[leftSliceBound:rightSliceBound], s.Copy())
	}
	wg.Wait()
	return
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
