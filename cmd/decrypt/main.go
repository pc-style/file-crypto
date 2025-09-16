package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	doublestar "github.com/bmatcuk/doublestar/v4"

	"file-crypto/internal/crypto"
	"file-crypto/internal/fs"
	"file-crypto/internal/system"
	"file-crypto/pkg/config"
)

type DecryptionStats struct {
	totalFiles      int64
	processedFiles  int64
	successfulFiles int64
	failedFiles     int64
	totalBytes      int64
	startTime       time.Time
	mutex           sync.RWMutex
}

func (s *DecryptionStats) incrementProcessed() {
	atomic.AddInt64(&s.processedFiles, 1)
}

func (s *DecryptionStats) incrementSuccessful() {
	atomic.AddInt64(&s.successfulFiles, 1)
}

func (s *DecryptionStats) incrementFailed() {
	atomic.AddInt64(&s.failedFiles, 1)
}

func (s *DecryptionStats) addBytes(bytes int64) {
	atomic.AddInt64(&s.totalBytes, bytes)
}

func (s *DecryptionStats) getStats() (int64, int64, int64, int64, int64) {
	return atomic.LoadInt64(&s.totalFiles),
		atomic.LoadInt64(&s.processedFiles),
		atomic.LoadInt64(&s.successfulFiles),
		atomic.LoadInt64(&s.failedFiles),
		atomic.LoadInt64(&s.totalBytes)
}

func main() {
	cfg, err := config.ParseFlags("decrypt")
	if err != nil {
		log.Fatalf("❌ Configuration error: %v", err)
	}

	// Quick confirmation (default Yes) unless -y/--yes provided
	if !cfg.AssumeYes {
		if !confirmProceed("Proceed with DECRYPTION (will remove .encrypted files)? [Y/n]: ") {
			fmt.Println("Aborted.")
			return
		}
	}

	cfg.PrintConfig("File Decryptor")

	// Load decryption key (passphrase for v4, RSA private key for v5)
	keyData, err := loadKey(cfg.KeyFile)
	if err != nil {
		log.Fatalf("❌ Failed to load key: %v", err)
	}

	// Create file operations handler
	fileOps := fs.NewSecureFileOperations(cfg.BufferSize)

	// Create system exclusions handler
	exclusions := system.NewExclusions(cfg.SystemExclusions)

	// Find files to decrypt
	fmt.Println("\n🔍 Scanning for files to decrypt...")
	files, err := findFilesToDecrypt(cfg.TargetDir, exclusions, cfg)
	if err != nil {
		log.Fatalf("❌ Failed to find files: %v", err)
	}

	if len(files) == 0 {
		fmt.Println("ℹ️  No encrypted files found to decrypt.")
		return
	}

	fmt.Printf("📁 Found %d files to decrypt\n", len(files))

	if cfg.DryRun {
		var totalBytes int64
		for _, f := range files {
			if sz, err := fs.GetFileSize(f); err == nil {
				totalBytes += sz
			}
		}
		fmt.Printf("\n[DRY-RUN] Would process %d files (%.2f MB)\n", len(files), float64(totalBytes)/(1024*1024))
		return
	}

	// Initialize statistics
	stats := &DecryptionStats{
		totalFiles: int64(len(files)),
		startTime:  time.Now(),
	}

	// Process files concurrently
	fmt.Printf("\n🚀 Starting decryption with %d workers...\n", cfg.MaxWorkers)
	err = processFilesParallel(files, cfg, keyData, fileOps, stats)
	if err != nil {
		log.Fatalf("❌ Decryption failed: %v", err)
	}

	// Print final statistics
	printFinalStats(stats, cfg.Benchmark)
}

func loadKey(keyFile string) ([]byte, error) {
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("key file '%s' not found", keyFile)
	}

	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	if len(keyData) == 0 {
		return nil, fmt.Errorf("key file is empty")
	}

	fmt.Printf("✅ Loaded decryption key (%d bytes)\n", len(keyData))
	fmt.Println("🔑 For v4 files: PBKDF2 passphrase; for v5 files: RSA private key (PEM/DER)")
	return keyData, nil
}

func findFilesToDecrypt(targetDir string, exclusions *system.Exclusions, cfg *config.Config) ([]string, error) {
	includeGlobs := parseGlobList(cfg.IncludeGlobs)
	excludeGlobs := parseGlobList(cfg.ExcludeGlobs)
	minSize := cfg.MinSizeBytes
	maxSize := cfg.MaxSizeBytes
	return fs.FindFiles(targetDir, func(path string, info os.FileInfo) bool {
		// Only process encrypted files
		if !fs.IsEncryptedFile(path) {
			return false
		}

		// Skip if should be excluded
		if exclusions.ShouldSkip(path) {
			return false
		}

		// Size filters
		if minSize > 0 && info.Size() < minSize {
			return false
		}
		if maxSize > 0 && info.Size() > maxSize {
			return false
		}

		// Glob filters
		if len(includeGlobs) > 0 && !matchAnyGlob(path, includeGlobs) {
			return false
		}
		if len(excludeGlobs) > 0 && matchAnyGlob(path, excludeGlobs) {
			return false
		}

		// Check minimum file size for valid encrypted file
		size, err := fs.GetFileSize(path)
		if err != nil || size < 84 { // Minimum header size
			return false
		}

		return true
	})
}

func processFilesParallel(files []string, cfg *config.Config, keyData []byte, fileOps *fs.SecureFileOperations, stats *DecryptionStats) error {
	// Create worker pool
	fileChan := make(chan string, len(files))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < cfg.MaxWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			decryptWorker(workerID, fileChan, cfg, keyData, fileOps, stats)
		}(i)
	}

	// Send files to workers
	for _, file := range files {
		fileChan <- file
	}
	close(fileChan)

	// Wait for all workers to complete
	wg.Wait()

	return nil
}

func decryptWorker(workerID int, fileChan <-chan string, cfg *config.Config, keyData []byte, fileOps *fs.SecureFileOperations, stats *DecryptionStats) {
	for filePath := range fileChan {
		err := decryptFile(filePath, cfg, keyData, fileOps, stats)
		if err != nil {
			fmt.Printf("❌ [Worker %d] Failed to decrypt %s: %v\n", workerID, filepath.Base(filePath), err)
			stats.incrementFailed()
		} else {
			stats.incrementSuccessful()
		}
		stats.incrementProcessed()
	}
}

func decryptFile(filePath string, cfg *config.Config, keyData []byte, fileOps *fs.SecureFileOperations, stats *DecryptionStats) error {
	// Read encrypted file data
	encryptedData, err := fileOps.ReadFileOptimized(filePath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %w", err)
	}

	stats.addBytes(int64(len(encryptedData)))

	// Decrypt data
	decryptedData, err := crypto.DecryptData(encryptedData, keyData)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	var finalData []byte = decryptedData

	// Decompress if compression was enabled during encryption
	if cfg.EnableCompression {
		// Try to decompress - if it fails, assume data wasn't compressed
		decompressed, err := crypto.DecompressData(decryptedData, len(decryptedData)*4) // Estimate
		if err != nil {
			if cfg.Verbose {
				fmt.Printf("⚠️ Decompression failed for %s, using decrypted data: %v\n", filepath.Base(filePath), err)
			}
			finalData = decryptedData
		} else {
			finalData = decompressed
			if cfg.Verbose {
				fmt.Printf("📦 Decompressed %s: %d -> %d bytes\n",
					filepath.Base(filePath), len(decryptedData), len(decompressed))
			}
		}
	}

	// Write decrypted file
	outputPath := fs.GetOutputPath(filePath, false)
	err = fileOps.WriteFileOptimized(outputPath, finalData)
	if err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	// Remove encrypted file
	err = os.Remove(filePath)
	if err != nil {
		if cfg.Verbose {
			fmt.Printf("⚠️ Failed to remove encrypted file %s: %v\n", filepath.Base(filePath), err)
		}
	}

	// Progress reporting
	totalFiles, processed, _, _, totalBytes := stats.getStats()
	if cfg.Benchmark {
		elapsed := time.Since(stats.startTime).Seconds()
		if elapsed > 0 {
			rate := float64(totalBytes) / elapsed
			rateStr := formatRate(rate)
			fmt.Printf("✅ [%d/%d] %s -> %s (%s)\n",
				processed, totalFiles, filepath.Base(filePath), filepath.Base(outputPath), rateStr)
		}
	} else {
		fmt.Printf("✅ [%d/%d] %s -> %s\n",
			processed, totalFiles, filepath.Base(filePath), filepath.Base(outputPath))
	}

	return nil
}

func printFinalStats(stats *DecryptionStats, benchmark bool) {
	total, _, successful, failed, totalBytes := stats.getStats()
	elapsed := time.Since(stats.startTime)

	fmt.Printf("\n📊 Decryption Complete!\n")
	fmt.Printf("   ✅ Successful: %d\n", successful)
	fmt.Printf("   ❌ Failed: %d\n", failed)
	fmt.Printf("   ⏱️  Time: %.2f seconds\n", elapsed.Seconds())

	if benchmark && elapsed.Seconds() > 0 {
		rate := float64(totalBytes) / elapsed.Seconds()
		rateStr := formatRate(rate)
		totalMB := float64(totalBytes) / (1024 * 1024)
		fmt.Printf("   📈 Rate: %s\n", rateStr)
		fmt.Printf("   📊 Data: %.1f MB processed\n", totalMB)
	} else if elapsed.Seconds() > 0 {
		fileRate := float64(total) / elapsed.Seconds()
		fmt.Printf("   📈 Rate: %.1f files/sec\n", fileRate)
	}
}

// parseGlobList and matchAnyGlob shared helpers (duplicated minimally to avoid extra package deps)
func parseGlobList(csv string) []string {
	var res []string
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}

func matchAnyGlob(path string, patterns []string) bool {
	unix := strings.ReplaceAll(path, "\\", "/")
	for _, pat := range patterns {
		pat = strings.ReplaceAll(pat, "\\", "/")
		// doublestar supports ** so policy globs can match nested directories.
		if ok, err := doublestar.Match(pat, unix); err == nil && ok {
			return true
		}
	}
	return false
}

func formatRate(bytesPerSec float64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytesPerSec >= GB:
		return fmt.Sprintf("%.1f GB/s", bytesPerSec/GB)
	case bytesPerSec >= MB:
		return fmt.Sprintf("%.1f MB/s", bytesPerSec/MB)
	case bytesPerSec >= KB:
		return fmt.Sprintf("%.1f KB/s", bytesPerSec/KB)
	default:
		return fmt.Sprintf("%.1f B/s", bytesPerSec)
	}
}

func confirmProceed(prompt string) bool {
	fmt.Print(prompt)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	s := strings.TrimSpace(strings.ToLower(line))
	if s == "" {
		return true
	}
	return s == "y" || s == "yes"
}
