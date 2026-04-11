package backup

import (
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

var (
	zstdEncoderOnce sync.Once
	zstdDecoderOnce sync.Once
	zstdEncoder     *zstd.Encoder
	zstdDecoder     *zstd.Decoder
)

func getEncoder() *zstd.Encoder {
	zstdEncoderOnce.Do(func() {
		zstdEncoder, _ = zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.SpeedDefault),
			zstd.WithEncoderConcurrency(1),
		)
	})
	return zstdEncoder
}

func getDecoder() *zstd.Decoder {
	zstdDecoderOnce.Do(func() {
		zstdDecoder, _ = zstd.NewReader(nil)
	})
	return zstdDecoder
}

// maybeZstdCompress compresses raw with zstd and returns the smaller
// representation. If compression does not shrink the data, raw is returned
// as-is with an empty compression tag.
func maybeZstdCompress(raw []byte) (stored []byte, compression string, uncompressedSize int) {
	uncompressedSize = len(raw)
	compressed := getEncoder().EncodeAll(raw, make([]byte, 0, len(raw)))
	if len(compressed) < len(raw) {
		return compressed, "zstd", uncompressedSize
	}
	return raw, "", uncompressedSize
}

// maybeDecompressStored decompresses stored bytes when compression is "zstd".
// For empty or unrecognized compression tags, raw bytes are returned unchanged.
func maybeDecompressStored(stored []byte, compression string) ([]byte, error) {
	if compression == "" || compression == "none" {
		return stored, nil
	}
	if compression == "zstd" {
		out, err := getDecoder().DecodeAll(stored, nil)
		if err != nil {
			return nil, fmt.Errorf("zstd decompress: %w", err)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported compression %q", compression)
}

var zstdFrameMagic = []byte{0x28, 0xB5, 0x2F, 0xFD}

func looksLikeZstdFrame(b []byte) bool {
	return len(b) >= 4 && b[0] == zstdFrameMagic[0] && b[1] == zstdFrameMagic[1] &&
		b[2] == zstdFrameMagic[2] && b[3] == zstdFrameMagic[3]
}

// maybeDecompressStoredOrInferZstd uses metadata first, then falls back to zstd
// frame detection when compression tags are missing.
func maybeDecompressStoredOrInferZstd(stored []byte, compression string) ([]byte, error) {
	out, err := maybeDecompressStored(stored, compression)
	if err != nil {
		return nil, err
	}
	if compression != "" && compression != "none" {
		return out, nil
	}
	if looksLikeZstdFrame(out) {
		decoded, err := getDecoder().DecodeAll(out, nil)
		if err == nil {
			return decoded, nil
		}
	}
	return out, nil
}
