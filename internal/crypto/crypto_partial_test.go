package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEncryptPartialRoundTrip(t *testing.T) {
	encryptor, err := NewEncryptor([]byte("partial-passphrase"))
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}
	defer encryptor.SecureClear()

	original := bytes.Repeat([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), 512)

	encrypted, err := encryptor.EncryptPartial(original, 20, 2)
	if err != nil {
		t.Fatalf("partial encryption failed: %v", err)
	}

	if len(encrypted) <= len(original) {
		t.Fatalf("expected header in encrypted output, got size %d", len(encrypted))
	}

	version := binary.BigEndian.Uint32(encrypted[:4])
	if version != EncryptionVersionV6 {
		t.Fatalf("expected version %d, got %d", EncryptionVersionV6, version)
	}

	header, headerSize, err := parseHeaderV6(encrypted)
	if err != nil {
		t.Fatalf("failed to parse partial header: %v", err)
	}
	if len(header.Segments) == 0 {
		t.Fatalf("expected at least one segment in partial header")
	}

	payload := encrypted[headerSize:]
	diffSegments := 0
	for _, seg := range header.Segments {
		start := int(seg.Offset)
		end := start + int(seg.Length)
		if end > len(payload) || end > len(original) {
			t.Fatalf("segment exceeds payload bounds")
		}
		if !bytes.Equal(payload[start:end], original[start:end]) {
			diffSegments++
		}
	}
	if diffSegments == 0 {
		t.Fatalf("expected encrypted segments to differ from original data")
	}

	decrypted, err := DecryptData(encrypted, []byte("partial-passphrase"))
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Fatalf("decrypted data did not match original")
	}
}
