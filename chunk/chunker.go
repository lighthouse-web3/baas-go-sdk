package chunk

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	sdktypes "github.com/lighthouse-web3/baas-go-sdk/types"
)

var gearTable = [256]uint32{
	0x9c0b346e, 0x2f12f54b, 0xc9b4c1db, 0x08ed4f08, 0x509c2de5, 0x9a9a7be7, 0x986e5867, 0x588735ca,
	0x79d7eabe, 0x2f344c2b, 0x1947ba01, 0xa046cfe7, 0x21bd6cef, 0x2d0e1e9d, 0xf73e7b4d, 0x369c0edc,
	0xb4ea55c5, 0x07a1644a, 0x1c7999f2, 0xbd7f89ab, 0x7f1d8983, 0xe8d10f2f, 0x54c4b77c, 0x5db0118f,
	0xdda12b45, 0x2e2eaa68, 0x78b0f758, 0x95fcad77, 0x2ac44fbd, 0x50d6181f, 0x5f595296, 0xbb79e6ff,
	0xf1e7a936, 0xbc0872bb, 0xdd1f338a, 0xb9594333, 0x0896fc09, 0x1cf1f3bb, 0xe3ce1d95, 0x17da5f26,
	0xabb1eb32, 0x1dc55eba, 0xc0884868, 0x42c218a3, 0xc40235d0, 0x22e07339, 0x2aeeb4cd, 0xb2da5e8a,
	0x66ebec5f, 0x73b2866b, 0x3a5e73d4, 0x8540074e, 0x7777224b, 0x7d122def, 0x11c0f6e7, 0x9b690279,
	0x3242622c, 0x271e5819, 0x8607ace7, 0xea05b841, 0xff3abdda, 0xb9180938, 0x1f7eb662, 0x23e88d8a,
	0x851f64c3, 0xd0ea9a55, 0xe5707edf, 0xd5c0236b, 0xc3d5393f, 0x6615f5a9, 0x0ab17af6, 0x1e0a3e33,
	0xe67abd44, 0xccd03da8, 0x943ba46d, 0x559abe86, 0xb0cfdf72, 0x8871f208, 0x6a6ae88c, 0x2e4f69c4,
	0x91e0625c, 0x7215e84a, 0x8974258c, 0xc4b3e08d, 0x09b732e6, 0xc71355a2, 0x786f5ade, 0x0df4b5fc,
	0x38ab684b, 0x4d38f518, 0x87bdeebb, 0xab435824, 0xc83d25a9, 0x420daecf, 0xf99ecd74, 0xf7ade2d2,
	0x20f5338d, 0x128197ca, 0x16e8233e, 0x032c7d2e, 0x733eac18, 0x7bbb793f, 0xc8102f25, 0x85a90acd,
	0x2640a9aa, 0x721b7dde, 0x03409f18, 0x29c35482, 0xc086acac, 0x7a6ac662, 0xdfb1161b, 0x154cc765,
	0xc5e98d14, 0xcdc2358e, 0xe4494345, 0x87713a04, 0x4d8ab9e3, 0x5e93fe0b, 0x5e48944c, 0xe421e750,
	0x4216712d, 0x36e4fca1, 0x9a514e59, 0x96b51f02, 0xdfcfe5cb, 0xaa360bd1, 0x1c43ce7a, 0xaafd0b62,
	0x528bbe76, 0xc97c1b59, 0x2c78aba5, 0x4ddde05e, 0x1ee6a8aa, 0x887f0ec0, 0x66afbd3c, 0x0a26fa4b,
	0x902f364f, 0x31c0b0e9, 0x6993312d, 0x591bbe3e, 0xa9b0ef9d, 0xbf985107, 0xd8949f94, 0x5c30375e,
	0xea6c079e, 0x0d9da57d, 0x13626095, 0x2fd26bd1, 0xd472c867, 0x110dad5b, 0x54388784, 0x32b70a2a,
	0xffc7be79, 0xb92895fd, 0x53d10506, 0xb3bb368d, 0x1eaf3f6e, 0x7571279d, 0x152daf35, 0x104f181f,
	0x7f799ac1, 0xf750898a, 0x2db2430a, 0xacfb906d, 0x3b3eaa88, 0x3ee92269, 0x3acd1dfe, 0x6593bf2d,
	0xe3ade174, 0x378c8e9e, 0x55f6eebc, 0xf7807d08, 0x6bb86bee, 0x05afad22, 0x9b3a7519, 0x477a6e5a,
	0x887cf9f4, 0xd8889414, 0x9f79e39b, 0x2158f165, 0x71219527, 0xb3602f89, 0x1c8441ca, 0x908e6a4d,
	0x590dbbd3, 0xc9c0d604, 0x99931c28, 0x1cdaeccb, 0xe4bfe526, 0x20573268, 0x48088547, 0x50c82db1,
	0x7d5effe4, 0x3bd7bbd1, 0x13e757c5, 0x19463fae, 0x011021d1, 0x1dc30e5a, 0x61449949, 0x3a884033,
	0xd1d25b7c, 0xbe33b74f, 0x56865913, 0x7d5d3e38, 0x2631d81d, 0x3a7b7b9a, 0xd6de37c3, 0x504b4a7a,
	0xa4c0b0d4, 0xf4a5c9b5, 0x047ef985, 0xdf9c9628, 0xce848a52, 0x7493cecd, 0xa06e2c0a, 0xe5214a41,
	0x8c3a19af, 0xdf2d1519, 0x207d5c5d, 0x9652d2b7, 0x98aa95fb, 0x4c049527, 0x07cb4179, 0xff70a92e,
	0xa75d8c7d, 0xa5ef31f0, 0xa5bfa530, 0x54487e45, 0xe9ff1e5e, 0x11ba61ab, 0xe7ae3a0a, 0x602b75d0,
	0x5007f2e6, 0x1d332ede, 0x4ae4d43a, 0x590ed2f8, 0x173df845, 0x9c1fdff3, 0x3e5e4594, 0xd7754d4d,
	0x8502e5fd, 0x5c9ef0d4, 0x477c6c96, 0x02022e78, 0x34ff1720, 0xdddeab27, 0x8b98b2b0, 0x208f8650,
	0xe5a896e5, 0x532220d5, 0xe72572aa, 0x4ed3b804, 0x2e2e7298, 0x0914153e, 0x587b68aa, 0xe60a10a8,
}

func ilog2(n int) int {
	bits := 0
	v := uint(n)
	for v > 1 {
		v >>= 1
		bits++
	}
	return bits
}

// Chunker implements streaming FastCDC.
type Chunker struct {
	buf      []byte
	gearHash uint32
	pos      int
	minSize  int
	avgSize  int
	maxSize  int
	maskS    uint32
	maskL    uint32
}

// NewChunker creates a Chunker with the given options.
func NewChunker(opts sdktypes.ChunkOptions) *Chunker {
	bits := ilog2(opts.AvgSize)
	return &Chunker{
		minSize: opts.MinSize,
		avgSize: opts.AvgSize,
		maxSize: opts.MaxSize,
		maskS:   (1 << (bits + 1)) - 1,
		maskL:   (1 << (bits - 1)) - 1,
	}
}

// Push feeds data into the chunker and returns any complete chunks.
func (c *Chunker) Push(data []byte) [][]byte {
	c.buf = append(c.buf, data...)
	var out [][]byte

	for c.pos < len(c.buf) {
		c.gearHash = (c.gearHash<<1 + gearTable[c.buf[c.pos]]) & 0xFFFFFFFF
		c.pos++

		if c.pos < c.minSize {
			continue
		}

		cut := c.pos >= c.maxSize
		if !cut {
			mask := c.maskS
			if c.pos >= c.avgSize {
				mask = c.maskL
			}
			cut = (c.gearHash & mask) == 0
		}

		if cut {
			chunk := make([]byte, c.pos)
			copy(chunk, c.buf[:c.pos])
			out = append(out, chunk)
			c.buf = c.buf[c.pos:]
			c.pos = 0
			c.gearHash = 0
		}
	}

	return out
}

// Flush returns any remaining buffered data as the final chunk.
func (c *Chunker) Flush() []byte {
	if len(c.buf) == 0 {
		return nil
	}
	remaining := make([]byte, len(c.buf))
	copy(remaining, c.buf)
	c.buf = nil
	c.pos = 0
	c.gearHash = 0
	return remaining
}

// SHA256Hex computes the lowercase hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ChunkFile reads a file and returns all chunks via FastCDC.
func ChunkFile(filePath string, opts sdktypes.ChunkOptions) ([]sdktypes.ChunkData, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cdc := NewChunker(opts)
	buf := make([]byte, 32*1024*1024)
	var chunks []sdktypes.ChunkData

	for {
		n, err := f.Read(buf)
		if n > 0 {
			for _, raw := range cdc.Push(buf[:n]) {
				chunks = append(chunks, sdktypes.ChunkData{
					Hash: SHA256Hex(raw),
					Data: raw,
					Size: len(raw),
				})
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	if last := cdc.Flush(); last != nil {
		chunks = append(chunks, sdktypes.ChunkData{
			Hash: SHA256Hex(last),
			Data: last,
			Size: len(last),
		})
	}

	return chunks, nil
}
