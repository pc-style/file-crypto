package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

const (
	EncryptionVersionV4 = 4
	EncryptionVersionV5 = 5
	EncryptionVersionV6 = 6

	SaltSize         = 32
	SessionIDSize    = 16
	NonceSize        = 12
	TagSize          = 16
	ChunkSize        = 1024 * 1024 // 1MB chunks for fixed-size padding
	PBKDF2Iterations = 100000
)

// Build-time embedded public/private keys (base64 encoded).
// Set with: -ldflags "-X 'file-crypto/internal/crypto.EmbeddedPublicKeyBase64=BASE64_DER'"
//
//	-ldflags "-X 'file-crypto/internal/crypto.EmbeddedPrivateKeyBase64=BASE64_PEM'"
var (
	EmbeddedPublicKeyBase64  string
	EmbeddedPrivateKeyBase64 string
)

// EncryptionMode identifies how data key is derived and stored
type EncryptionMode uint8

const (
	ModeSymmetricPBKDF2  EncryptionMode = 1
	ModePublicKeyHybrid  EncryptionMode = 2
	ModeSymmetricPartial EncryptionMode = 3
)

type Encryptor struct {
	rawKey    []byte
	salt      []byte
	sessionID []byte
	key       []byte
}

type DecryptionHeaderV4 struct {
	Version      uint32
	Salt         []byte
	SessionID    []byte
	Nonce        []byte
	Tag          []byte
	OriginalSize uint32
	ChunksNeeded uint32
}

type DecryptionHeaderV5 struct {
	Version      uint32
	Mode         EncryptionMode
	SessionID    []byte
	Nonce        []byte
	Tag          []byte
	OriginalSize uint32
	ChunksNeeded uint32
	WrappedKey   []byte
}

type PartialSegment struct {
	Offset uint64
	Length uint64
	Nonce  [NonceSize]byte
	Tag    [TagSize]byte
}

type DecryptionHeaderV6 struct {
	Version      uint32
	Mode         EncryptionMode
	Salt         []byte
	SessionID    []byte
	OriginalSize uint64
	Segments     []PartialSegment
}

func NewEncryptor(rawKey []byte) (*Encryptor, error) {
	if len(rawKey) == 0 {
		return nil, errors.New("raw key cannot be empty")
	}

	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	sessionID := make([]byte, SessionIDSize)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	key := pbkdf2.Key(rawKey, salt, PBKDF2Iterations, 32, sha256.New)

	return &Encryptor{
		rawKey:    rawKey,
		salt:      salt,
		sessionID: sessionID,
		key:       key,
	}, nil
}

func (e *Encryptor) EncryptData(data []byte) ([]byte, error) {
	// Calculate padding for fixed-size chunks
	originalSize := len(data)
	chunksNeeded := (originalSize + ChunkSize - 1) / ChunkSize
	paddedSize := chunksNeeded * ChunkSize
	paddingNeeded := paddedSize - originalSize

	// Add random padding
	padding := make([]byte, paddingNeeded)
	if _, err := rand.Read(padding); err != nil {
		return nil, fmt.Errorf("failed to generate padding: %w", err)
	}
	paddedData := append(data, padding...)

	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create cipher
	aead, err := chacha20poly1305.New(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Encrypt with authentication
	ciphertext := aead.Seal(nil, nonce, paddedData, nil)

	// Split ciphertext and tag
	if len(ciphertext) < TagSize {
		return nil, errors.New("ciphertext too short")
	}
	encryptedData := ciphertext[:len(ciphertext)-TagSize]
	tag := ciphertext[len(ciphertext)-TagSize:]

	// Create header
	header := make([]byte, 0, 4+SaltSize+SessionIDSize+NonceSize+TagSize+4+4)

	// Version (4 bytes)
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, EncryptionVersionV4)
	header = append(header, versionBytes...)

	// Salt (32 bytes)
	header = append(header, e.salt...)

	// Session ID (16 bytes)
	header = append(header, e.sessionID...)

	// Nonce (12 bytes)
	header = append(header, nonce...)

	// Tag (16 bytes)
	header = append(header, tag...)

	// Original size (4 bytes)
	originalSizeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(originalSizeBytes, uint32(originalSize))
	header = append(header, originalSizeBytes...)

	// Chunks needed (4 bytes)
	chunksNeededBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(chunksNeededBytes, uint32(chunksNeeded))
	header = append(header, chunksNeededBytes...)

	// Combine header and encrypted data
	result := append(header, encryptedData...)
	return result, nil
}

func (e *Encryptor) EncryptPartial(data []byte, percent int, segments int) ([]byte, error) {
	if percent >= 100 || len(data) == 0 {
		return e.EncryptData(data)
	}

	if percent <= 0 {
		percent = 10
	}
	if segments <= 0 {
		segments = 1
	}

	totalBytes := len(data) * percent / 100
	if totalBytes == 0 && len(data) > 0 {
		totalBytes = 1
	}
	if totalBytes > len(data) {
		totalBytes = len(data)
	}
	if totalBytes == 0 {
		return e.EncryptData(data)
	}
	if segments > totalBytes {
		segments = totalBytes
	}

	lengths := make([]int, segments)
	base := totalBytes / segments
	remainder := totalBytes % segments
	for i := 0; i < segments; i++ {
		lengths[i] = base
		if remainder > 0 {
			lengths[i]++
			remainder--
		}
	}

	offsets := make([]int, segments)
	dataLen := len(data)
	for i := 0; i < segments; i++ {
		windowStart := 0
		if segments > 0 {
			windowStart = i * dataLen / segments
		}
		start := windowStart
		if start+lengths[i] > dataLen {
			start = dataLen - lengths[i]
		}
		if start < 0 {
			start = 0
		}
		offsets[i] = start
	}

	for i := 1; i < segments; i++ {
		prevEnd := offsets[i-1] + lengths[i-1]
		maxStart := dataLen - lengths[i]
		if maxStart < 0 {
			maxStart = 0
		}
		if prevEnd > maxStart {
			prevEnd = maxStart
		}
		if offsets[i] < prevEnd {
			offsets[i] = prevEnd
		}
	}

	aead, err := chacha20poly1305.New(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	processed := make([]byte, dataLen)
	copy(processed, data)

	segmentMetadata := make([]PartialSegment, 0, segments)

	for i := 0; i < segments; i++ {
		length := lengths[i]
		if length <= 0 {
			continue
		}
		start := offsets[i]
		if start < 0 || start+length > dataLen {
			continue
		}
		nonce := make([]byte, NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}

		ciphertext := aead.Seal(nil, nonce, data[start:start+length], nil)
		if len(ciphertext) < length+TagSize {
			return nil, errors.New("ciphertext too short for partial segment")
		}

		copy(processed[start:start+length], ciphertext[:length])

		var nonceArr [NonceSize]byte
		copy(nonceArr[:], nonce)
		var tagArr [TagSize]byte
		copy(tagArr[:], ciphertext[length:])

		segmentMetadata = append(segmentMetadata, PartialSegment{
			Offset: uint64(start),
			Length: uint64(length),
			Nonce:  nonceArr,
			Tag:    tagArr,
		})
	}

	if len(segmentMetadata) == 0 {
		return e.EncryptData(data)
	}

	header := make([]byte, 0, 4+1+SaltSize+SessionIDSize+8+2+len(segmentMetadata)*(8+8+NonceSize+TagSize))
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, EncryptionVersionV6)
	header = append(header, versionBytes...)
	header = append(header, byte(ModeSymmetricPartial))
	header = append(header, e.salt...)
	header = append(header, e.sessionID...)
	originalSizeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(originalSizeBytes, uint64(len(data)))
	header = append(header, originalSizeBytes...)
	segmentCountBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(segmentCountBytes, uint16(len(segmentMetadata)))
	header = append(header, segmentCountBytes...)
	for _, meta := range segmentMetadata {
		offsetBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(offsetBytes, meta.Offset)
		header = append(header, offsetBytes...)
		lengthBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lengthBytes, meta.Length)
		header = append(header, lengthBytes...)
		header = append(header, meta.Nonce[:]...)
		header = append(header, meta.Tag[:]...)
	}

	return append(header, processed...), nil
}

func DecryptData(encryptedData []byte, keyData []byte) ([]byte, error) {
	if len(encryptedData) < 4 {
		return nil, errors.New("encrypted data too short")
	}

	version := binary.BigEndian.Uint32(encryptedData[:4])
	switch version {
	case EncryptionVersionV4:
		header, err := parseHeaderV4(encryptedData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse header v4: %w", err)
		}

		// Derive key from passphrase
		key := pbkdf2.Key(keyData, header.Salt, PBKDF2Iterations, 32, sha256.New)

		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher: %w", err)
		}

		headerSize := 4 + SaltSize + SessionIDSize + NonceSize + TagSize + 4 + 4
		if len(encryptedData) < headerSize {
			return nil, errors.New("encrypted data too short")
		}
		ciphertext := encryptedData[headerSize:]
		ciphertextWithTag := append(ciphertext, header.Tag...)

		paddedData, err := aead.Open(nil, header.Nonce, ciphertextWithTag, nil)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}

		if len(paddedData) < int(header.OriginalSize) {
			return nil, errors.New("decrypted data smaller than original size")
		}
		return paddedData[:header.OriginalSize], nil

	case EncryptionVersionV5:
		header, headerSize, err := parseHeaderV5(encryptedData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse header v5: %w", err)
		}
		if header.Mode != ModePublicKeyHybrid {
			return nil, fmt.Errorf("unsupported mode in v5 header: %d", header.Mode)
		}

		// Parse RSA private key from keyData (PEM or DER, PKCS1 or PKCS8)
		privKey, err := parseRSAPrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}

		// Unwrap data key using RSA-OAEP(SHA-256)
		dataKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, header.WrappedKey, header.SessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt wrapped key: %w", err)
		}
		if len(dataKey) != 32 {
			return nil, errors.New("invalid unwrapped data key size")
		}

		aead, err := chacha20poly1305.New(dataKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher: %w", err)
		}

		if len(encryptedData) < headerSize {
			return nil, errors.New("encrypted data too short")
		}
		ciphertext := encryptedData[headerSize:]
		ciphertextWithTag := append(ciphertext, header.Tag...)

		paddedData, err := aead.Open(nil, header.Nonce, ciphertextWithTag, nil)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}
		if len(paddedData) < int(header.OriginalSize) {
			return nil, errors.New("decrypted data smaller than original size")
		}
		return paddedData[:header.OriginalSize], nil

	case EncryptionVersionV6:
		header, headerSize, err := parseHeaderV6(encryptedData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse header v6: %w", err)
		}
		if header.Mode != ModeSymmetricPartial {
			return nil, fmt.Errorf("unsupported mode in v6 header: %d", header.Mode)
		}

		key := pbkdf2.Key(keyData, header.Salt, PBKDF2Iterations, 32, sha256.New)
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher: %w", err)
		}

		if len(encryptedData) < headerSize {
			return nil, errors.New("encrypted data too short")
		}
		payload := encryptedData[headerSize:]
		if uint64(len(payload)) < header.OriginalSize {
			return nil, errors.New("encrypted data too short")
		}

		result := make([]byte, int(header.OriginalSize))
		copy(result, payload[:int(header.OriginalSize)])

		for _, segment := range header.Segments {
			if segment.Length == 0 {
				continue
			}
			start := int(segment.Offset)
			length := int(segment.Length)
			if start < 0 || length < 0 || start+length > len(result) {
				return nil, errors.New("invalid partial segment metadata")
			}
			ciphertext := make([]byte, length+TagSize)
			copy(ciphertext, payload[start:start+length])
			copy(ciphertext[length:], segment.Tag[:])

			plaintext, err := aead.Open(nil, segment.Nonce[:], ciphertext, nil)
			if err != nil {
				return nil, fmt.Errorf("decryption failed: %w", err)
			}
			copy(result[start:start+length], plaintext)
		}

		return result, nil

	default:
		return nil, fmt.Errorf("unsupported encryption version: %d", version)
	}
}

func parseHeaderV4(data []byte) (*DecryptionHeaderV4, error) {
	if len(data) < 4+SaltSize+SessionIDSize+NonceSize+TagSize+4+4 {
		return nil, errors.New("data too short for header v4")
	}

	header := &DecryptionHeaderV4{}
	offset := 0

	header.Version = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	header.Salt = make([]byte, SaltSize)
	copy(header.Salt, data[offset:offset+SaltSize])
	offset += SaltSize

	header.SessionID = make([]byte, SessionIDSize)
	copy(header.SessionID, data[offset:offset+SessionIDSize])
	offset += SessionIDSize

	header.Nonce = make([]byte, NonceSize)
	copy(header.Nonce, data[offset:offset+NonceSize])
	offset += NonceSize

	header.Tag = make([]byte, TagSize)
	copy(header.Tag, data[offset:offset+TagSize])
	offset += TagSize

	header.OriginalSize = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	header.ChunksNeeded = binary.BigEndian.Uint32(data[offset : offset+4])

	return header, nil
}

// parseHeaderV5 returns header and total header size in bytes
func parseHeaderV5(data []byte) (*DecryptionHeaderV5, int, error) {
	minFixed := 4 + 1 + SessionIDSize + NonceSize + TagSize + 4 + 4 + 2
	if len(data) < minFixed {
		return nil, 0, errors.New("data too short for header v5")
	}
	offset := 0
	header := &DecryptionHeaderV5{}

	header.Version = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	header.Mode = EncryptionMode(data[offset])
	offset += 1

	header.SessionID = make([]byte, SessionIDSize)
	copy(header.SessionID, data[offset:offset+SessionIDSize])
	offset += SessionIDSize

	header.Nonce = make([]byte, NonceSize)
	copy(header.Nonce, data[offset:offset+NonceSize])
	offset += NonceSize

	header.Tag = make([]byte, TagSize)
	copy(header.Tag, data[offset:offset+TagSize])
	offset += TagSize

	header.OriginalSize = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	header.ChunksNeeded = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	wrappedLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if len(data) < offset+wrappedLen {
		return nil, 0, errors.New("data too short for wrapped key")
	}
	header.WrappedKey = make([]byte, wrappedLen)
	copy(header.WrappedKey, data[offset:offset+wrappedLen])
	offset += wrappedLen

	return header, offset, nil
}

func parseHeaderV6(data []byte) (*DecryptionHeaderV6, int, error) {
	minFixed := 4 + 1 + SaltSize + SessionIDSize + 8 + 2
	if len(data) < minFixed {
		return nil, 0, errors.New("data too short for header v6")
	}

	offset := 0
	header := &DecryptionHeaderV6{}

	header.Version = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	header.Mode = EncryptionMode(data[offset])
	offset += 1

	header.Salt = make([]byte, SaltSize)
	copy(header.Salt, data[offset:offset+SaltSize])
	offset += SaltSize

	header.SessionID = make([]byte, SessionIDSize)
	copy(header.SessionID, data[offset:offset+SessionIDSize])
	offset += SessionIDSize

	header.OriginalSize = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	segmentCount := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	header.Segments = make([]PartialSegment, segmentCount)
	for i := 0; i < int(segmentCount); i++ {
		needed := 8 + 8 + NonceSize + TagSize
		if len(data) < offset+needed {
			return nil, 0, errors.New("data too short for partial segment metadata")
		}

		header.Segments[i].Offset = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8

		header.Segments[i].Length = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8

		copy(header.Segments[i].Nonce[:], data[offset:offset+NonceSize])
		offset += NonceSize

		copy(header.Segments[i].Tag[:], data[offset:offset+TagSize])
		offset += TagSize
	}

	return header, offset, nil
}

func (e *Encryptor) SecureClear() {
	// Overwrite sensitive data with zeros
	if e.rawKey != nil {
		for i := range e.rawKey {
			e.rawKey[i] = 0
		}
		e.rawKey = nil
	}
	if e.salt != nil {
		for i := range e.salt {
			e.salt[i] = 0
		}
		e.salt = nil
	}
	if e.sessionID != nil {
		for i := range e.sessionID {
			e.sessionID[i] = 0
		}
		e.sessionID = nil
	}
	if e.key != nil {
		for i := range e.key {
			e.key[i] = 0
		}
		e.key = nil
	}
}

func SecureRandom(size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return nil, fmt.Errorf("failed to generate secure random data: %w", err)
	}
	return data, nil
}

// PublicEncryptor uses an embedded RSA public key to wrap a randomly generated data key.
type PublicEncryptor struct {
	publicKey *rsa.PublicKey
}

// HasEmbeddedPublicKey reports whether a public key was embedded at build-time.
func HasEmbeddedPublicKey() bool {
	return EmbeddedPublicKeyBase64 != ""
}

// HasEmbeddedPrivateKey reports whether a private key payload was embedded for simulation builds.
func HasEmbeddedPrivateKey() bool {
	return EmbeddedPrivateKeyBase64 != ""
}

// NewPublicEncryptorFromEmbedded constructs a PublicEncryptor from the build-time embedded key.
func NewPublicEncryptorFromEmbedded() (*PublicEncryptor, error) {
	if EmbeddedPublicKeyBase64 == "" {
		return nil, errors.New("no embedded public key present")
	}
	pub, err := parseRSAPublicKeyBase64(EmbeddedPublicKeyBase64)
	if err != nil {
		return nil, err
	}
	return &PublicEncryptor{publicKey: pub}, nil
}

// EncryptData implements encryption with the v5 public-key header.
func (p *PublicEncryptor) EncryptData(data []byte) ([]byte, error) {
	// Calculate padding
	originalSize := len(data)
	chunksNeeded := (originalSize + ChunkSize - 1) / ChunkSize
	paddedSize := chunksNeeded * ChunkSize
	paddingNeeded := paddedSize - originalSize

	padding := make([]byte, paddingNeeded)
	if _, err := rand.Read(padding); err != nil {
		return nil, fmt.Errorf("failed to generate padding: %w", err)
	}
	paddedData := append(data, padding...)

	// Generate data key and nonce
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Session ID (used as OAEP label)
	sessionID := make([]byte, SessionIDSize)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// AEAD encrypt
	aead, err := chacha20poly1305.New(dataKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, paddedData, nil)
	if len(ciphertext) < TagSize {
		return nil, errors.New("ciphertext too short")
	}
	encryptedData := ciphertext[:len(ciphertext)-TagSize]
	tag := ciphertext[len(ciphertext)-TagSize:]

	// Wrap data key with RSA-OAEP
	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, p.publicKey, dataKey, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap data key: %w", err)
	}

	// Build v5 header
	header := make([]byte, 0, 4+1+SessionIDSize+NonceSize+TagSize+4+4+2+len(wrappedKey))

	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, EncryptionVersionV5)
	header = append(header, versionBytes...)

	header = append(header, byte(ModePublicKeyHybrid))
	header = append(header, sessionID...)
	header = append(header, nonce...)
	header = append(header, tag...)

	originalSizeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(originalSizeBytes, uint32(originalSize))
	header = append(header, originalSizeBytes...)

	chunksNeededBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(chunksNeededBytes, uint32(chunksNeeded))
	header = append(header, chunksNeededBytes...)

	wrappedLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(wrappedLenBytes, uint16(len(wrappedKey)))
	header = append(header, wrappedLenBytes...)
	header = append(header, wrappedKey...)

	return append(header, encryptedData...), nil
}

// SecureClear for PublicEncryptor clears nothing sensitive (no private material held).
func (p *PublicEncryptor) SecureClear() {}

func parseRSAPublicKeyBase64(b64 string) (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode embedded public key: %w", err)
	}
	// Try PKIX first
	if pub, err2 := x509.ParsePKIXPublicKey(der); err2 == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
	}
	// Try PKCS1
	if rsaPub, err2 := x509.ParsePKCS1PublicKey(der); err2 == nil {
		return rsaPub, nil
	}
	return nil, errors.New("unsupported public key DER format; expected PKIX or PKCS1 RSA")
}

// GetEmbeddedPrivateKey decodes the embedded private key payload.
func GetEmbeddedPrivateKey() ([]byte, error) {
	if EmbeddedPrivateKeyBase64 == "" {
		return nil, errors.New("no embedded private key present")
	}
	data, err := base64.StdEncoding.DecodeString(EmbeddedPrivateKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode embedded private key: %w", err)
	}
	return data, nil
}

func parseRSAPrivateKey(pemOrDer []byte) (*rsa.PrivateKey, error) {
	// Try PEM decoding
	if block, _ := pem.Decode(pemOrDer); block != nil {
		switch block.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rsaPriv, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("not an RSA private key")
			}
			return rsaPriv, nil
		default:
			// Try parsing as PKCS8 regardless
			if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if rsaPriv, ok := key.(*rsa.PrivateKey); ok {
					return rsaPriv, nil
				}
			}
			return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
		}
	}
	// Try raw DER PKCS1
	if key, err := x509.ParsePKCS1PrivateKey(pemOrDer); err == nil {
		return key, nil
	}
	// Try raw DER PKCS8
	if key, err := x509.ParsePKCS8PrivateKey(pemOrDer); err == nil {
		if rsaPriv, ok := key.(*rsa.PrivateKey); ok {
			return rsaPriv, nil
		}
		return nil, errors.New("not an RSA private key")
	}
	return nil, errors.New("failed to parse RSA private key; expected PEM or DER (PKCS1/PKCS8)")
}
