// Package phe provides the basic implementation of two partial
// homomorphic encryption cryptosystems
//
// In this implementation we are focusing on the following properties:
// 1. Addition over plaintext
// 2. Multiplication of a plaintext by a ciphertext
//
// In both of the cryptosystems implemented, the addition over
// plaintext is equal to multiplication in the ciphertext.
//
// Similarly, the multiplication of a ciphertext with a plaintext
// is equal to raising the ciphertext to the power of the plaintext
//
// The main difference between Paillier and Benaloh cryptosystems
// is that in the former we can work with operations over big
// integers while with the latter we trade the max size of plaintext
// and a bit of key generation and decryption for speed of encryption
//
// Assuming that the multiplication time of two N bit sized numbers
// is equal to T(N).
//
// Paillier takes O(Security * T(Security)) per encryption and
// decryption. We can do operations with plaintext modulo bits
// magnitude O(Security ** 2)
//
// For Benaloh cryptosystem an extra parameter r should be specified
// which will signify the plaintext modulo. To make the implementation
// easier, r was set to be a prime. If the method is called with a
// nonprime r then it will be increased until it reaches a prime.
//
// To generate the keys, we need to find a prime p such that (p - 1, r) = r.
// The current crypto/rand Prime function is impractical for bigger r
// so a new function was implemented in PSI/rand to find the prime p quicker
//
// The encryption in Benaloh cryptosystem takes O(T(Security) * log r)
// and the decryption takes
// O(Security * T(Security) + (Security * log(r) + T(Security)) * r ** 0.5)
// using the meet-in-the-middle approach to finding the discrete logarithm.
// This makes the decryption time a bottleneck in the overall time. In cases
// when we need to decrypt a few ciphertexts such as PSI Cardinal, it is
// more desirable than Paillier
//
// A significant disadvantage is that we need to store O(Security * r ** 0.5)
// memory only to be able to decrypt the ciphertext. This makes the Benaloh
// cryptosystem impractical for many applications but ideal for small scale
// operations
//
// For Vector encryption EncryptVectorUint64 and EncryptVectorUint64Parallel
// should be used.
//
// For Vector decryption DecryptVector and DecryptVectorParallel should be
// used
//
// Note that the functions above work for any struct that implements PublicKey
// interface and SecretKey interface respectively
//
// It is necessary to copy the keys using Copy function if you're planning
// using the key over multiple go routines
package phe
