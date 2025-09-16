package fs

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type SecureFileOperations struct {
	bufferSize int
	mutex      sync.RWMutex
}

func NewSecureFileOperations(bufferSize int) *SecureFileOperations {
	if bufferSize <= 0 {
		bufferSize = 64 * 1024 // Default 64KB
	}
	return &SecureFileOperations{
		bufferSize: bufferSize,
	}
}

func (sfo *SecureFileOperations) ReadFileOptimized(path string) ([]byte, error) {
	sfo.mutex.RLock()
	defer sfo.mutex.RUnlock()

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file %s: %w", path, err)
	}

	size := stat.Size()
	if size == 0 {
		return []byte{}, nil
	}

	// For small files, read all at once
	if size < int64(sfo.bufferSize) {
		data := make([]byte, size)
		_, err := io.ReadFull(file, data)
		if err != nil {
			return nil, fmt.Errorf("failed to read small file %s: %w", path, err)
		}
		return data, nil
	}

	// For larger files, use buffered reading
	var chunks [][]byte
	buffer := make([]byte, sfo.bufferSize)

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buffer[:n])
			chunks = append(chunks, chunk)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", path, err)
		}
	}

	// Combine chunks
	totalSize := 0
	for _, chunk := range chunks {
		totalSize += len(chunk)
	}

	result := make([]byte, 0, totalSize)
	for _, chunk := range chunks {
		result = append(result, chunk...)
	}

	return result, nil
}

func (sfo *SecureFileOperations) WriteFileOptimized(path string, data []byte) error {
	sfo.mutex.Lock()
	defer sfo.mutex.Unlock()

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	defer file.Close()

	// For small data, write all at once
	if len(data) < sfo.bufferSize {
		_, err := file.Write(data)
		if err != nil {
			return fmt.Errorf("failed to write small file %s: %w", path, err)
		}
		return file.Sync()
	}

	// For larger data, use buffered writing
	for i := 0; i < len(data); i += sfo.bufferSize {
		end := i + sfo.bufferSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[i:end]
		_, err := file.Write(chunk)
		if err != nil {
			return fmt.Errorf("failed to write chunk to file %s: %w", path, err)
		}
	}

	return file.Sync()
}

func (sfo *SecureFileOperations) SecureDelete(path string) error {
	sfo.mutex.Lock()
	defer sfo.mutex.Unlock()

	stat, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file for secure deletion %s: %w", path, err)
	}

	size := stat.Size()
	if size == 0 {
		return os.Remove(path)
	}

	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file for secure deletion %s: %w", path, err)
	}
	defer file.Close()

	// Overwrite with random data multiple times
	for pass := 0; pass < 3; pass++ {
		if _, err := file.Seek(0, 0); err != nil {
			return fmt.Errorf("failed to seek in file during secure deletion %s: %w", path, err)
		}

		written := int64(0)
		for written < size {
			chunkSize := sfo.bufferSize
			if written+int64(chunkSize) > size {
				chunkSize = int(size - written)
			}

			randomData := make([]byte, chunkSize)
			if _, err := rand.Read(randomData); err != nil {
				return fmt.Errorf("failed to generate random data for secure deletion %s: %w", path, err)
			}

			n, err := file.Write(randomData)
			if err != nil {
				return fmt.Errorf("failed to write random data during secure deletion %s: %w", path, err)
			}
			written += int64(n)
		}

		if err := file.Sync(); err != nil {
			return fmt.Errorf("failed to sync during secure deletion %s: %w", path, err)
		}
	}

	// Final overwrite with zeros
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek for zero overwrite %s: %w", path, err)
	}

	written := int64(0)
	zeroBuffer := make([]byte, sfo.bufferSize)
	for written < size {
		chunkSize := sfo.bufferSize
		if written+int64(chunkSize) > size {
			chunkSize = int(size - written)
		}

		n, err := file.Write(zeroBuffer[:chunkSize])
		if err != nil {
			return fmt.Errorf("failed to write zeros during secure deletion %s: %w", path, err)
		}
		written += int64(n)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync zero overwrite %s: %w", path, err)
	}

	file.Close()

	// Finally remove the file
	return os.Remove(path)
}

func FindFiles(rootDir string, includeFunc func(string, os.FileInfo) bool) ([]string, error) {
	var files []string
	var mutex sync.Mutex

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip files/directories we can't access
			return nil
		}

		if info.IsDir() {
			return nil
		}

		if includeFunc(path, info) {
			mutex.Lock()
			files = append(files, path)
			mutex.Unlock()
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", rootDir, err)
	}

	return files, nil
}

func IsEncryptedFile(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".encrypted")
}

func GetOutputPath(inputPath string, encrypt bool) string {
	if encrypt {
		return inputPath + ".encrypted"
	}
	// For decryption, remove .encrypted extension
	if strings.HasSuffix(strings.ToLower(inputPath), ".encrypted") {
		return inputPath[:len(inputPath)-10] // Remove ".encrypted"
	}
	return inputPath + ".decrypted"
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func GetFileSize(path string) (int64, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return stat.Size(), nil
}