/*
 * Copyright (c) 2019, Psiphon Inc.
 * All rights reserved.
 *
 * Released under utls licence:
 * https://github.com/refraction-networking/utls/blob/master/LICENSE
 */

// This code is a pared down version of:
// https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/158caea562287284cc3fa5fcd1b3c97b1addf659/psiphon/common/prng/prng.go

package tls

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"golang.org/x/crypto/sha3"
	"io"
	"math"
	"math/rand"
	"sync"
)

const _PRNGSeedLength = 32

// _PRNGSeed is a PRNG seed.
type _PRNGSeed [_PRNGSeedLength]byte

// _NewPRNGSeed creates a new PRNG seed using crypto/rand.Read.
func _NewPRNGSeed() (*_PRNGSeed, error) {
	seed := new(_PRNGSeed)
	_, err := crypto_rand.Read(seed[:])
	if err != nil {
		return nil, err
	}
	return seed, nil
}

// prng is a seeded, unbiased PRNG based on SHAKE256. that is suitable for use
// cases such as obfuscation. Seeding is based on crypto/rand.Read.
//
// This PRNG is _not_ for security use cases including production cryptographic
// key generation.
//
// It is safe to make concurrent calls to a PRNG instance.
//
// PRNG conforms to io.Reader and math/rand.Source, with additional helper
// functions.
type prng struct {
	rand              *rand.Rand
	randomStreamMutex sync.Mutex
	randomStream      sha3.ShakeHash
}

// newPRNG generates a seed and creates a PRNG with that seed.
func newPRNG() (*prng, error) {
	seed, err := _NewPRNGSeed()
	if err != nil {
		return nil, err
	}
	return newPRNGWithSeed(seed)
}

// newPRNGWithSeed initializes a new PRNG using an existing seed.
func newPRNGWithSeed(seed *_PRNGSeed) (*prng, error) {
	shake := sha3.NewShake256()
	_, err := shake.Write(seed[:])
	if err != nil {
		return nil, err
	}
	p := &prng{
		randomStream: shake,
	}
	p.rand = rand.New(p)
	return p, nil
}

// _Read reads random bytes from the PRNG stream into b. _Read conforms to
// io.Reader and always returns len(p), nil.
func (p *prng) _Read(b []byte) (int, error) {
	p.randomStreamMutex.Lock()
	defer p.randomStreamMutex.Unlock()

	// ShakeHash.Read never returns an error:
	// https://godoc.org/golang.org/x/crypto/sha3#ShakeHash
	_, _ = io.ReadFull(p.randomStream, b)

	return len(b), nil
}

// Int63 is equivilent to math/read.Int63.
func (p *prng) Int63() int64 {
	i := p._Uint64()
	return int64(i & (1<<63 - 1))
}

// Int63 is equivilent to math/read._Uint64.
func (p *prng) _Uint64() uint64 {
	var b [8]byte
	p._Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}

// Seed must exist in order to use a PRNG as a math/rand.Source. This call is
// not supported and ignored.
func (p *prng) Seed(_ int64) {
}

// _FlipWeightedCoin returns the result of a weighted
// random coin flip. If the weight is 0.5, the outcome
// is equally likely to be true or false. If the weight
// is 1.0, the outcome is always true, and if the
// weight is 0.0, the outcome is always false.
//
// Input weights > 1.0 are treated as 1.0.
func (p *prng) _FlipWeightedCoin(weight float64) bool {
	if weight > 1.0 {
		weight = 1.0
	}
	f := float64(p.Int63()) / float64(math.MaxInt64)
	return f > 1.0-weight
}

// _Intn is equivilent to math/read._Intn, except it returns 0 if n <= 0
// instead of panicking.
func (p *prng) _Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return p.rand.Intn(n)
}

// Intn is equivilent to math/read._Perm.
func (p *prng) _Perm(n int) []int {
	return p.rand.Perm(n)
}
