package crypto

import (
	"fmt"

	"github.com/pierrec/lz4/v4"
)

func CompressData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	// Pre-allocate buffer with some extra space
	compressed := make([]byte, lz4.CompressBlockBound(len(data)))

	n, err := lz4.CompressBlock(data, compressed, nil)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	// Return only the compressed portion
	return compressed[:n], nil
}

func DecompressData(compressed []byte, originalSize int) ([]byte, error) {
	if len(compressed) == 0 {
		return compressed, nil
	}

	if originalSize <= 0 {
		originalSize = len(compressed) * 4
	}

	decompressed := make([]byte, originalSize)
	n, err := lz4.UncompressBlock(compressed, decompressed)
	if err != nil {
		return nil, fmt.Errorf("decompression failed: %w", err)
	}
	if n > originalSize {
		return nil, fmt.Errorf("decompressed size overflow: %d > %d", n, originalSize)
	}

	return decompressed[:n], nil
}

func CalculateCompressionRatio(original, compressed []byte) float64 {
	if len(original) == 0 {
		return 1.0
	}
	return float64(len(compressed)) / float64(len(original))
}
