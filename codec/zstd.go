package codec

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

// MaybeZstdCompress compresses raw with zstd and returns the smaller representation.
func MaybeZstdCompress(raw []byte) (stored []byte, compression string, uncompressedSize int) {
	uncompressedSize = len(raw)
	compressed := getEncoder().EncodeAll(raw, make([]byte, 0, len(raw)))
	if len(compressed) < len(raw) {
		return compressed, "zstd", uncompressedSize
	}
	return raw, "", uncompressedSize
}

// MaybeDecompressStored decompresses stored bytes when compression is "zstd".
func MaybeDecompressStored(stored []byte, compression string) ([]byte, error) {
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

// MaybeDecompressStoredOrInferZstd uses metadata first, then falls back to zstd frame detection.
func MaybeDecompressStoredOrInferZstd(stored []byte, compression string) ([]byte, error) {
	out, err := MaybeDecompressStored(stored, compression)
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
