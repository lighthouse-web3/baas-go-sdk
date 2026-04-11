package backup

import (
	"encoding/base64"
	"strconv"
)

// BloomFilter provides fast probabilistic membership testing.
//
// Cross-language spec (must be identical in every SDK):
//
//	h1 = parse_uint32_hex(hash[0:8])
//	h2 = parse_uint32_hex(hash[8:16])
//	position_i = (h1 + i * h2) % numBits
type BloomFilter struct {
	bytes     []byte
	numBits   uint32
	numHashes int
}

// NewBloomFilter creates a bloom filter from a server response.
func NewBloomFilter(resp BloomResponse) (*BloomFilter, error) {
	data, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, err
	}
	return &BloomFilter{
		bytes:     data,
		numBits:   uint32(resp.NumBits),
		numHashes: resp.NumHashes,
	}, nil
}

// Test returns true if the hash might exist in the filter (may be a false positive).
func (bf *BloomFilter) Test(hash string) bool {
	h1 := parseHex32(hash[0:8])
	h2 := parseHex32(hash[8:16])
	for i := uint32(0); i < uint32(bf.numHashes); i++ {
		pos := (h1 + i*h2) % bf.numBits
		if bf.bytes[pos>>3]&(1<<(pos&7)) == 0 {
			return false
		}
	}
	return true
}

func parseHex32(s string) uint32 {
	v, _ := strconv.ParseUint(s, 16, 32)
	return uint32(v)
}

// EmptyBloom returns a bloom filter that reports everything as "new".
type emptyBloom struct{}

func (emptyBloom) Test(_ string) bool { return false }

// BloomTester is the interface shared by BloomFilter and the empty sentinel.
type BloomTester interface {
	Test(hash string) bool
}

// NewEmptyBloom returns a BloomTester that always returns false.
func NewEmptyBloom() BloomTester {
	return emptyBloom{}
}
