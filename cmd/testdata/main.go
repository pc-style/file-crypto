package main
import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)
type config struct {
	OutDir           string
	DocumentCount    int
	PDFCount         int
	NoteCount        int
	SpreadsheetCount int
	ImageCount       int
	MinBytes         int
	MaxBytes         int
	Seed             int64
	Force            bool
	Profile          string
}
type generator struct {
	cfg config
	rnd *rand.Rand
}
func main() {
	cfg := parseFlags()
	if err := cfg.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}
	if cfg.Force {
		if err := os.RemoveAll(cfg.OutDir); err != nil {
			fmt.Fprintf(os.Stderr, "❌ failed to clear output directory: %v\n", err)
			os.Exit(1)
		}
	}
	if err := ensureEmptyDir(cfg.OutDir); err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}
	rnd := rand.New(rand.NewSource(cfg.seed()))
	gen := generator{cfg: cfg, rnd: rnd}
	if err := gen.run(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ generation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✨ Test data generated in %s\n", cfg.OutDir)
}
func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.OutDir, "out", filepath.Join("testdata"), "Output directory for generated corpus")
	flag.IntVar(&cfg.DocumentCount, "documents", 12, "Number of DOCX reports to generate")
	flag.IntVar(&cfg.PDFCount, "pdfs", 6, "Number of PDF summaries to generate")
	flag.IntVar(&cfg.NoteCount, "notes", 8, "Number of Markdown/Text notes to generate")
	flag.IntVar(&cfg.SpreadsheetCount, "spreadsheets", 4, "Number of CSV spreadsheets to generate")
	flag.IntVar(&cfg.ImageCount, "images", 6, "Number of PNG marketing assets to generate")
	flag.IntVar(&cfg.MinBytes, "min-bytes", 2048, "Minimum approximate size (bytes) for generated files")
	flag.IntVar(&cfg.MaxBytes, "max-bytes", 65536, "Maximum approximate size (bytes) for generated files")
	flag.Int64Var(&cfg.Seed, "seed", 0, "Optional deterministic seed (defaults to current time)")
	flag.BoolVar(&cfg.Force, "force", false, "Allow overwriting an existing directory by clearing it first")
	flag.StringVar(&cfg.Profile, "profile", "corp", "Dataset profile: corp (shared drive) or unix (root filesystem)")
	flag.Parse()
	cfg.Profile = strings.ToLower(strings.TrimSpace(cfg.Profile))
	switch cfg.Profile {
	case "", "corp", "corporate", "share", "shared", "office":
		cfg.Profile = "corp"
	case "unix", "root", "posix", "mac", "macos", "linux":
		cfg.Profile = "unix"
	}
	return cfg
}
func (c config) validate() error {
	if c.OutDir == "" {
		return errors.New("output directory is required")
	}
	if c.MinBytes <= 0 {
		return errors.New("min-bytes must be positive")
	}
	if c.MaxBytes < c.MinBytes {
		return errors.New("max-bytes must be greater than or equal to min-bytes")
	}
	if c.DocumentCount < 0 || c.PDFCount < 0 || c.NoteCount < 0 || c.SpreadsheetCount < 0 || c.ImageCount < 0 {
		return errors.New("file counts cannot be negative")
	}
	switch c.Profile {
	case "corp", "unix":
	default:
		return fmt.Errorf("invalid profile %q (must be 'corp' or 'unix')", c.Profile)
	}
	return nil
}
func (c config) seed() int64 {
	if c.Seed != 0 {
		return c.Seed
	}
	return time.Now().UnixNano()
}
func ensureEmptyDir(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return os.MkdirAll(path, 0o755)
	}
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("output directory %s is not empty (use -force to overwrite)", path)
	}
	return nil
}
func (g *generator) run() error {
	switch g.cfg.Profile {
	case "corp":
		return g.generateCorporateDataset()
	case "unix":
		return g.generateUnixRootDataset()
	default:
		return fmt.Errorf("unsupported profile %q", g.cfg.Profile)
	}
}
func (g *generator) generateCorporateDataset() error {
	structure := []string{
		filepath.Join(g.cfg.OutDir, "Documents", "Reports"),
		filepath.Join(g.cfg.OutDir, "Documents", "Policies"),
		filepath.Join(g.cfg.OutDir, "Documents", "Notes"),
		filepath.Join(g.cfg.OutDir, "Finance", "Budgets"),
		filepath.Join(g.cfg.OutDir, "Finance", "Statements"),
		filepath.Join(g.cfg.OutDir, "HR", "Reviews"),
		filepath.Join(g.cfg.OutDir, "Marketing", "Assets"),
		filepath.Join(g.cfg.OutDir, "Marketing", "Campaigns"),
		filepath.Join(g.cfg.OutDir, "IT", "Configs"),
		filepath.Join(g.cfg.OutDir, "IT", "Scripts"),
		filepath.Join(g.cfg.OutDir, "Operations", "Backups"),
	}
	for _, dir := range structure {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create %s: %w", dir, err)
		}
	}
	if g.cfg.DocumentCount == 0 && g.cfg.PDFCount == 0 && g.cfg.NoteCount == 0 && g.cfg.SpreadsheetCount == 0 && g.cfg.ImageCount == 0 {
		g.cfg.DocumentCount = 12
		g.cfg.PDFCount = 6
		g.cfg.NoteCount = 8
		g.cfg.SpreadsheetCount = 4
		g.cfg.ImageCount = 6
	}
	if err := g.generateDocuments(); err != nil {
		return err
	}
	if err := g.generatePDFs(); err != nil {
		return err
	}
	if err := g.generateNotes(); err != nil {
		return err
	}
	if err := g.generateSpreadsheets(); err != nil {
		return err
	}
	if err := g.generateImages(); err != nil {
		return err
	}
	if err := g.generateConfigs(); err != nil {
		return err
	}
	if err := g.generateScripts(); err != nil {
		return err
	}
	if err := g.generateArchives(); err != nil {
		return err
	}
	return g.generateCorporateReadme()
}
func (g *generator) generateUnixRootDataset() error {
	root := g.cfg.OutDir
	structure := []string{
		filepath.Join(root, "bin"),
		filepath.Join(root, "etc"),
		filepath.Join(root, "etc", "ssh"),
		filepath.Join(root, "etc", "nginx"),
		filepath.Join(root, "etc", "systemd", "system"),
		filepath.Join(root, "etc", "cron.d"),
		filepath.Join(root, "etc", "security"),
		filepath.Join(root, "etc", "profile.d"),
		filepath.Join(root, "etc", "sudoers.d"),
		filepath.Join(root, "etc", "paths.d"),
		filepath.Join(root, "usr", "local", "bin"),
		filepath.Join(root, "usr", "local", "etc"),
		filepath.Join(root, "usr", "local", "lib"),
		filepath.Join(root, "usr", "local", "share", "acme"),
		filepath.Join(root, "var", "log"),
		filepath.Join(root, "var", "backups"),
		filepath.Join(root, "var", "tmp"),
		filepath.Join(root, "Library", "LaunchAgents"),
		filepath.Join(root, "Library", "Preferences"),
		filepath.Join(root, "System", "Library", "LaunchDaemons"),
		filepath.Join(root, "opt", "acme", "bin"),
		filepath.Join(root, "opt", "acme", "lib"),
		filepath.Join(root, "opt", "acme", "etc"),
		filepath.Join(root, "private", "etc"),
		filepath.Join(root, "tmp"),
		filepath.Join(root, "Users", "Shared"),
	}
	for _, dir := range structure {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create %s: %w", dir, err)
		}
	}
	host := g.randomUnixHostname()
	domain := g.randomInternalDomain()
	agentName := g.randomUnixServiceName()
	execPath := fmt.Sprintf("/opt/acme/bin/%s", agentName)
	if err := os.WriteFile(filepath.Join(root, "etc", "hosts"), []byte(g.renderEtcHosts(host, domain)), 0o644); err != nil {
		return fmt.Errorf("hosts: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "fstab"), []byte(g.renderFstabFile()), 0o644); err != nil {
		return fmt.Errorf("fstab: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte(g.renderOSRelease()), 0o644); err != nil {
		return fmt.Errorf("os-release: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "ssh", "sshd_config"), []byte(g.renderSSHDConfig()), 0o600); err != nil {
		return fmt.Errorf("sshd_config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "nginx", "nginx.conf"), []byte(g.renderNginxConfig(domain)), 0o644); err != nil {
		return fmt.Errorf("nginx.conf: %w", err)
	}
	serviceBase := fmt.Sprintf("%s.service", agentName)
	timerBase := fmt.Sprintf("%s.timer", agentName)
	if err := os.WriteFile(filepath.Join(root, "etc", "systemd", "system", serviceBase), []byte(g.renderSystemdService(agentName, execPath, g.randomServiceDescription())), 0o644); err != nil {
		return fmt.Errorf("systemd service: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "systemd", "system", timerBase), []byte(g.renderSystemdTimer(agentName)), 0o644); err != nil {
		return fmt.Errorf("systemd timer: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "cron.d", "nightly-maintenance"), []byte(g.renderCronJob(agentName)), 0o644); err != nil {
		return fmt.Errorf("cron: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "security", "audit.yaml"), []byte(g.renderAuditYAML()), 0o644); err != nil {
		return fmt.Errorf("audit.yaml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "profile.d", "company.sh"), []byte(g.renderProfileScript(domain)), 0o755); err != nil {
		return fmt.Errorf("profile.d: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "paths.d", "devops-tools"), []byte(g.renderPathsFile()), 0o644); err != nil {
		return fmt.Errorf("paths.d: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "sudoers.d", "devops"), []byte(g.renderSudoersFile()), 0o440); err != nil {
		return fmt.Errorf("sudoers: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "environment"), []byte(g.renderEnvironmentFile(domain)), 0o644); err != nil {
		return fmt.Errorf("environment: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "local", "bin", "backup-sync.sh"), []byte(g.renderSystemShellScript(agentName, domain)), 0o755); err != nil {
		return fmt.Errorf("backup-sync.sh: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "local", "bin", "cleanup.py"), []byte(g.renderCleanupPythonScript(domain)), 0o755); err != nil {
		return fmt.Errorf("cleanup.py: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "local", "etc", "agent.json"), g.renderUnixAgentConfig(agentName, domain), 0o644); err != nil {
		return fmt.Errorf("agent.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "local", "etc", "feature-flags.yaml"), []byte(g.renderUnixFeatureFlagsFile()), 0o644); err != nil {
		return fmt.Errorf("feature-flags.yaml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "local", "share", "acme", "manifest.yaml"), []byte(g.renderManifestYAML(agentName)), 0o644); err != nil {
		return fmt.Errorf("manifest.yaml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "local", "share", "acme", "dashboard.json"), g.renderDashboardJSON(domain), 0o644); err != nil {
		return fmt.Errorf("dashboard.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "Library", "LaunchAgents", "com.acme.sync.plist"), []byte(g.renderLaunchAgentPlist("com.acme.sync", "/usr/local/bin/backup-sync.sh")), 0o644); err != nil {
		return fmt.Errorf("LaunchAgent: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "Library", "Preferences", "com.acme.analytics.plist"), []byte(g.renderPreferencesPlist("com.acme.analytics", domain)), 0o644); err != nil {
		return fmt.Errorf("Preferences plist: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "System", "Library", "LaunchDaemons", "com.acme.metrics.plist"), []byte(g.renderLaunchDaemonPlist("com.acme.metrics", execPath)), 0o644); err != nil {
		return fmt.Errorf("LaunchDaemon: %w", err)
	}
	dylibName := fmt.Sprintf("lib%s.dylib", strings.ReplaceAll(agentName, "-", ""))
	if err := g.writeBinaryFile(filepath.Join(root, "bin", "acme-tool"), 16384, g.randomBinaryHeader(), 0o755); err != nil {
		return fmt.Errorf("bin/acme-tool: %w", err)
	}
	if err := g.writeBinaryFile(filepath.Join(root, "opt", "acme", "bin", agentName), 24576, g.randomBinaryHeader(), 0o755); err != nil {
		return fmt.Errorf("opt binary: %w", err)
	}
	if err := g.writeBinaryFile(filepath.Join(root, "opt", "acme", "lib", dylibName), 28672, machOHeader(), 0o644); err != nil {
		return fmt.Errorf("opt dylib: %w", err)
	}
	if err := g.writeBinaryFile(filepath.Join(root, "usr", "local", "lib", "libmetrics.so"), 28672, []byte("\x7fELF\x02\x01\x01"), 0o644); err != nil {
		return fmt.Errorf("libmetrics.so: %w", err)
	}
	backupPath := filepath.Join(root, "var", "backups", fmt.Sprintf("%s-snapshot.tar.gz", agentName))
	if err := g.writeSystemBackupTar(backupPath, agentName, domain); err != nil {
		return fmt.Errorf("backup tar: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "var", "backups", "passwd.bak"), []byte(g.renderPasswdBackup()), 0o600); err != nil {
		return fmt.Errorf("passwd.bak: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "var", "log", "system.log"), []byte(g.renderSystemLog(host)), 0o644); err != nil {
		return fmt.Errorf("system.log: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "var", "log", "auth.log"), []byte(g.renderAuthLog(host)), 0o600); err != nil {
		return fmt.Errorf("auth.log: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "var", "log", "nginx-access.log"), []byte(g.renderAccessLog(domain)), 0o644); err != nil {
		return fmt.Errorf("access.log: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "var", "tmp", "deploy.lock"), []byte(g.renderDeployLock(agentName)), 0o600); err != nil {
		return fmt.Errorf("deploy.lock: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "opt", "acme", "etc", "agent.conf"), []byte(g.renderAgentConf(agentName, domain)), 0o644); err != nil {
		return fmt.Errorf("agent.conf: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "private", "etc", "keystore.json"), g.renderKeystore(), 0o600); err != nil {
		return fmt.Errorf("keystore.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "tmp", "install.log"), []byte(g.renderInstallerLog()), 0o600); err != nil {
		return fmt.Errorf("install.log: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "tmp", "update-status.json"), g.renderUpdateStatus(domain), 0o644); err != nil {
		return fmt.Errorf("update-status.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "Users", "Shared", "maintenance-readme.txt"), []byte(g.renderMaintenanceReadme(agentName)), 0o644); err != nil {
		return fmt.Errorf("maintenance readme: %w", err)
	}
	return g.generateUnixReadme(host, domain, agentName)
}
func (g *generator) randomSize() int {
	if g.cfg.MinBytes == g.cfg.MaxBytes {
		return g.cfg.MinBytes
	}
	return g.cfg.MinBytes + g.rnd.Intn(g.cfg.MaxBytes-g.cfg.MinBytes+1)
}
func (g *generator) generateDocuments() error {
	reportDir := filepath.Join(g.cfg.OutDir, "Documents", "Reports")
	for i := 0; i < g.cfg.DocumentCount; i++ {
		title := g.randomReportTitle()
		target := g.randomSize()
		paragraphs := g.generateParagraphs(target, 90, 140)
		fileName := fmt.Sprintf("%s.docx", slugify(title))
		path := filepath.Join(reportDir, fileName)
		if err := writeDocx(path, title, paragraphs); err != nil {
			return fmt.Errorf("docx %s: %w", path, err)
		}
	}
	policyDir := filepath.Join(g.cfg.OutDir, "Documents", "Policies")
	policyCount := max(3, g.cfg.DocumentCount/4)
	for i := 0; i < policyCount; i++ {
		title := g.randomPolicyTitle()
		target := g.randomSize()
		paragraphs := g.generateParagraphs(target, 80, 120)
		fileName := fmt.Sprintf("%s.rtf", slugify(title))
		path := filepath.Join(policyDir, fileName)
		if err := os.WriteFile(path, []byte(renderRTF(title, paragraphs)), 0o644); err != nil {
			return fmt.Errorf("rtf %s: %w", path, err)
		}
	}
	return nil
}
func (g *generator) generatePDFs() error {
	reportDir := filepath.Join(g.cfg.OutDir, "Documents", "Reports")
	for i := 0; i < g.cfg.PDFCount; i++ {
		title := g.randomExecutiveSummaryTitle()
		target := g.randomSize()
		paragraphs := g.generateParagraphs(target, 70, 120)
		path := filepath.Join(reportDir, fmt.Sprintf("%s.pdf", slugify(title)))
		if err := writePDF(path, title, paragraphs); err != nil {
			return fmt.Errorf("pdf %s: %w", path, err)
		}
	}
	return nil
}
func (g *generator) generateNotes() error {
	notesDir := filepath.Join(g.cfg.OutDir, "Documents", "Notes")
	for i := 0; i < g.cfg.NoteCount; i++ {
		title := g.randomMeetingTitle()
		target := g.randomSize()
		content := g.renderMeetingNotes(title, target)
		var ext string
		if i%3 == 0 {
			ext = ".md"
		} else {
			ext = ".txt"
		}
		path := filepath.Join(notesDir, fmt.Sprintf("%s%s", slugify(title), ext))
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return fmt.Errorf("note %s: %w", path, err)
		}
	}
	return nil
}
func (g *generator) generateSpreadsheets() error {
	budgetDir := filepath.Join(g.cfg.OutDir, "Finance", "Budgets")
	for i := 0; i < g.cfg.SpreadsheetCount; i++ {
		title := fmt.Sprintf("%s budget forecast", g.randomDepartment())
		fileName := fmt.Sprintf("%s.csv", slugify(title))
		path := filepath.Join(budgetDir, fileName)
		rows := g.renderBudgetRows()
		if err := os.WriteFile(path, []byte(rows), 0o644); err != nil {
			return fmt.Errorf("csv %s: %w", path, err)
		}
	}
	return nil
}
func (g *generator) generateImages() error {
	assetDir := filepath.Join(g.cfg.OutDir, "Marketing", "Assets")
	for i := 0; i < g.cfg.ImageCount; i++ {
		title := fmt.Sprintf("%s campaign banner", g.randomCampaignName())
		fileName := fmt.Sprintf("%s.png", slugify(title))
		path := filepath.Join(assetDir, fileName)
		target := g.randomSize()
		if err := writeMarketingPNG(path, target, g.rnd); err != nil {
			return fmt.Errorf("png %s: %w", path, err)
		}
	}
	return nil
}
func (g *generator) generateConfigs() error {
	configDir := filepath.Join(g.cfg.OutDir, "IT", "Configs")
	envs := []string{"production", "staging", "qa"}
	yamlCount := max(3, g.cfg.DocumentCount/4)
	for i := 0; i < yamlCount; i++ {
		app := g.randomApplication()
		env := envs[i%len(envs)]
		name := fmt.Sprintf("%s-%s.yaml", slugify(app), env)
		path := filepath.Join(configDir, name)
		if err := os.WriteFile(path, []byte(g.renderServiceYAMLConfig(app, env)), 0o644); err != nil {
			return fmt.Errorf("yaml config %s: %w", path, err)
		}
	}
	jsonCount := max(2, g.cfg.NoteCount/3)
	for i := 0; i < jsonCount; i++ {
		app := g.randomApplication()
		data, err := g.renderFeatureJSONConfig(app)
		if err != nil {
			return fmt.Errorf("json config %s: %w", app, err)
		}
		name := fmt.Sprintf("%s-flags.json", slugify(app))
		path := filepath.Join(configDir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return fmt.Errorf("json config %s: %w", path, err)
		}
	}
	iniCount := max(2, g.cfg.SpreadsheetCount/3)
	for i := 0; i < iniCount; i++ {
		env := envs[(i+1)%len(envs)]
		region := g.pick(regions)
		name := fmt.Sprintf("%s-database.ini", env)
		path := filepath.Join(configDir, name)
		if err := os.WriteFile(path, []byte(g.renderDatabaseINIConfig(env, region)), 0o644); err != nil {
			return fmt.Errorf("ini config %s: %w", path, err)
		}
	}
	return nil
}
func (g *generator) generateScripts() error {
	scriptDir := filepath.Join(g.cfg.OutDir, "IT", "Scripts")
	shellName := fmt.Sprintf("%s-maintenance.sh", slugify(g.randomDepartment()))
	shellPath := filepath.Join(scriptDir, shellName)
	if err := os.WriteFile(shellPath, []byte(g.renderShellMaintenanceScript(shellName)), 0o755); err != nil {
		return fmt.Errorf("shell script %s: %w", shellPath, err)
	}
	pythonName := fmt.Sprintf("%s-metrics.py", slugify(g.randomApplication()))
	pythonPath := filepath.Join(scriptDir, pythonName)
	if err := os.WriteFile(pythonPath, []byte(g.renderPythonMetricsScript(pythonName)), 0o755); err != nil {
		return fmt.Errorf("python script %s: %w", pythonPath, err)
	}
	psName := fmt.Sprintf("%s-sync.ps1", slugify(g.randomApplication()))
	psPath := filepath.Join(scriptDir, psName)
	if err := os.WriteFile(psPath, []byte(g.renderPowerShellSyncScript(psName)), 0o644); err != nil {
		return fmt.Errorf("powershell script %s: %w", psPath, err)
	}
	return nil
}
func (g *generator) generateArchives() error {
	archiveDir := filepath.Join(g.cfg.OutDir, "Operations", "Backups")
	count := max(2, g.cfg.DocumentCount/6)
	for i := 0; i < count; i++ {
		dept := g.randomDepartment()
		year := time.Now().Year() - g.rnd.Intn(3)
		archiveName := fmt.Sprintf("%s-%d-export.zip", slugify(dept), year)
		path := filepath.Join(archiveDir, archiveName)
		entries := []zipEntry{
			{Name: "README.txt", Body: []byte(g.renderArchiveReadme(dept, year)), Mode: 0o644},
			{Name: "manifest.json", Body: g.renderBackupManifestJSON(dept, year), Mode: 0o644},
			{Name: fmt.Sprintf("reports/%s.csv", slugify(dept)), Body: []byte(g.renderBudgetRows()), Mode: 0o644},
			{Name: "docs/checklist.yaml", Body: []byte(g.renderArchiveChecklist()), Mode: 0o644},
		}
		if err := writeZipArchive(path, entries); err != nil {
			return fmt.Errorf("archive %s: %w", path, err)
		}
	}
	inventoryName := fmt.Sprintf("inventory-%d.json", time.Now().Year())
	inventoryPath := filepath.Join(archiveDir, inventoryName)
	if err := os.WriteFile(inventoryPath, g.renderBackupInventory(), 0o644); err != nil {
		return fmt.Errorf("inventory %s: %w", inventoryPath, err)
	}
	return nil
}
func (g *generator) generateCorporateReadme() error {
	lines := []string{
		"# Synthetic Corporate Dataset",
		"",
		"This directory was generated with the `testdata` utility that ships with File Crypto.",
		"It mimics a mid-sized company's document share with realistic file names, content,",
		"and directory layout so that encryption and recovery workflows can be rehearsed",
		"without touching production data.",
		"",
		"## Structure",
		"- Documents/Reports: Quarterly briefings, board updates (DOCX/PDF)",
		"- Documents/Policies: Employee handbooks and compliance addenda (RTF)",
		"- Documents/Notes: Meeting notes and retrospectives (TXT/MD)",
		"- Finance/Budgets: Department forecasts (CSV)",
		"- Marketing/Assets: Campaign collateral (PNG)",
		"- IT/Configs: Application YAML/JSON/INI configuration files",
		"- IT/Scripts: Automation scripts for Linux, Windows, and Python agents",
		"- Operations/Backups: Zipped data drops and inventory manifests",
		"",
		fmt.Sprintf("Generated: %s", time.Now().Format(time.RFC3339)),
	}
	return os.WriteFile(filepath.Join(g.cfg.OutDir, "README.md"), []byte(strings.Join(lines, "\n")), 0o644)
}
func (g *generator) randomReportTitle() string {
	quarter := quarters[g.rnd.Intn(len(quarters))]
	year := time.Now().Year() - g.rnd.Intn(2)
	topic := titleCase(g.pick(reportTopics))
	focus := titleCase(g.pick(reportFocus))
	return fmt.Sprintf("%s %d %s %s", quarter, year, topic, focus)
}
func (g *generator) randomPolicyTitle() string {
	adjective := titleCase(g.pick(policyAdjectives))
	subject := titleCase(g.pick(policySubjects))
	suffix := titleCase(g.pick(policySuffixes))
	return fmt.Sprintf("%s %s %s", adjective, subject, suffix)
}
func (g *generator) randomExecutiveSummaryTitle() string {
	qualifier := titleCase(g.pick(summaryQualifiers))
	subject := titleCase(g.pick(summarySubjects))
	year := time.Now().Year()
	return fmt.Sprintf("%s %s Overview %d", qualifier, subject, year)
}
func (g *generator) randomMeetingTitle() string {
	prefix := titleCase(g.pick(meetingPrefixes))
	dept := titleCase(g.randomDepartment())
	return fmt.Sprintf("%s %s Meeting", prefix, dept)
}
func (g *generator) randomApplication() string {
	return g.pick(applications)
}
func (g *generator) randomInternalDomain() string {
	return g.pick(internalDomains)
}
func (g *generator) randomUnixHostname() string {
	return g.pick(unixHostnames)
}
func (g *generator) randomUnixServiceName() string {
	return fmt.Sprintf("%s-%s", g.pick(unixServicePrefixes), g.pick(unixServiceSuffixes))
}
func (g *generator) randomServiceDescription() string {
	return g.pick(unixServiceDescriptions)
}
func (g *generator) renderMeetingNotes(title string, target int) string {
	date := g.randomRecentDate()
	attendees := g.randomAttendees()
	paragraphs := g.generateParagraphs(target, 60, 110)
	summary := paragraphs[:min(3, len(paragraphs))]
	actionCount := min(6, max(3, len(paragraphs)/2))
	actions := make([]string, actionCount)
	for i := range actions {
		actions[i] = fmt.Sprintf("- [ ] %s", titleCase(g.pick(actionItems)))
	}
	builder := &strings.Builder{}
	fmt.Fprintf(builder, "# %s\n", title)
	fmt.Fprintf(builder, "Date: %s\n", date.Format("2006-01-02"))
	fmt.Fprintf(builder, "Attendees: %s\n\n", strings.Join(attendees, ", "))
	builder.WriteString("## Summary\n")
	for _, para := range summary {
		builder.WriteString(para)
		builder.WriteString("\n\n")
	}
	builder.WriteString("## Discussion\n")
	for _, para := range paragraphs {
		builder.WriteString("- ")
		builder.WriteString(para)
		builder.WriteString("\n")
	}
	builder.WriteString("\n## Action Items\n")
	for _, action := range actions {
		builder.WriteString(action)
		builder.WriteString("\n")
	}
	return builder.String()
}
func (g *generator) renderServiceYAMLConfig(app, env string) string {
	domain := g.randomInternalDomain()
	cacheEnabled := g.rnd.Intn(2) == 0
	replicas := 2 + g.rnd.Intn(3)
	builder := &strings.Builder{}
	fmt.Fprintf(builder, "service: %s\n", slugify(app))
	fmt.Fprintf(builder, "environment: %s\n", env)
	fmt.Fprintf(builder, "version: v%d.%d.%d\n", 1+g.rnd.Intn(3), g.rnd.Intn(10), g.rnd.Intn(10))
	builder.WriteString("ingress:\n")
	fmt.Fprintf(builder, "  host: %s.%s\n", slugify(app), domain)
	builder.WriteString("  tls: true\n")
	builder.WriteString("database:\n")
	fmt.Fprintf(builder, "  engine: %s\n", g.pick(databaseEngines))
	fmt.Fprintf(builder, "  host: %s.%s\n", slugify(app)+"-db", domain)
	builder.WriteString("  port: 5432\n")
	fmt.Fprintf(builder, "  name: %s_%s\n", strings.ReplaceAll(strings.ToLower(app), " ", "_"), env)
	builder.WriteString("caching:\n")
	fmt.Fprintf(builder, "  enabled: %t\n", cacheEnabled)
	builder.WriteString("  provider: redis\n")
	builder.WriteString("autoscaling:\n")
	fmt.Fprintf(builder, "  min_replicas: %d\n", replicas)
	fmt.Fprintf(builder, "  max_replicas: %d\n", replicas+2+g.rnd.Intn(3))
	builder.WriteString("  cpu_target: 65\n")
	builder.WriteString("observability:\n")
	fmt.Fprintf(builder, "  grafana_dashboard: dashboards/%s.json\n", slugify(app))
	fmt.Fprintf(builder, "  alert_policy: alerts/%s-%s.yaml\n", slugify(app), env)
	return builder.String()
}
func (g *generator) renderFeatureJSONConfig(app string) ([]byte, error) {
	flags := map[string]bool{}
	enabled := g.rnd.Perm(len(featureFlags))
	for i := 0; i < min(5, len(featureFlags)); i++ {
		index := enabled[i]
		if index >= len(featureFlags) {
			continue
		}
		flags[featureFlags[index]] = g.rnd.Intn(3) != 0
	}
	payload := map[string]interface{}{
		"service":      slugify(app),
		"generated_at": time.Now().Format(time.RFC3339),
		"flags":        flags,
		"regions":      []string{g.pick(regions), g.pick(regions)},
		"rollout": map[string]interface{}{
			"percentage": 10 + g.rnd.Intn(80),
			"cohort":     g.pick(releaseCohorts),
		},
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	return data, nil
}
func (g *generator) renderDatabaseINIConfig(env, region string) string {
	builder := &strings.Builder{}
	builder.WriteString("[database]\n")
	fmt.Fprintf(builder, "host=%s.%s.internal\n", env, region)
	builder.WriteString("port=5432\n")
	builder.WriteString("user=service\n")
	builder.WriteString("password={{ vault.postgres.password }}\n")
	fmt.Fprintf(builder, "dbname=core_%s\n", env)
	builder.WriteString("sslmode=require\n")
	builder.WriteString("[replica]\n")
	fmt.Fprintf(builder, "host=%s-read.%s.internal\n", env, region)
	builder.WriteString("port=5432\n")
	builder.WriteString("role=readonly\n")
	return builder.String()
}
func (g *generator) renderShellMaintenanceScript(name string) string {
	commands := []string{
		"log() { echo \"$(date -u '+%Y-%m-%dT%H:%M:%SZ') $1\"; }",
		"log 'Starting weekly maintenance'",
		"systemctl stop app-web.service",
		"rm -rf /srv/cache/*",
		"pg_dump --format=custom core_production > /var/backups/core-production.dump",
		"systemctl start app-web.service",
		"log 'Maintenance complete'",
	}
	return renderBashScript(fmt.Sprintf("Maintenance script %s", name), commands)
}
func (g *generator) renderPythonMetricsScript(name string) string {
	builder := &strings.Builder{}
	builder.WriteString("#!/usr/bin/env python3\n")
	builder.WriteString("import json\nimport random\nimport time\n\n")
	builder.WriteString("def collect_metrics():\n")
	builder.WriteString("    return {\n")
	builder.WriteString("        \"service\": \"")
	builder.WriteString(strings.ReplaceAll(name, "-", "_"))
	builder.WriteString("\",\n")
	builder.WriteString("        \"timestamp\": time.time(),\n")
	builder.WriteString("        \"latency_ms\": round(random.uniform(120, 380), 2),\n")
	builder.WriteString("        \"error_rate\": round(random.random() / 10, 4),\n")
	builder.WriteString("    }\n\n")
	builder.WriteString("if __name__ == '__main__':\n")
	builder.WriteString("    payload = collect_metrics()\n")
	builder.WriteString("    with open('/var/tmp/metrics.json', 'w', encoding='utf-8') as handle:\n")
	builder.WriteString("        json.dump(payload, handle, indent=2)\n")
	builder.WriteString("    print('metrics written to /var/tmp/metrics.json')\n")
	return builder.String()
}
func (g *generator) renderPowerShellSyncScript(name string) string {
	builder := &strings.Builder{}
	builder.WriteString("param(\n    [string]$Destination = '\\\\fileserver\\archives'\n)\n\n")
	builder.WriteString("Write-Host 'Starting archive synchronisation'\n")
	builder.WriteString("$source = Join-Path $PSScriptRoot '..\\..\\Operations\\Backups'\n")
	builder.WriteString("$manifest = Join-Path $source '" + strings.ReplaceAll(name, "-", "_") + "-manifest.json'\n")
	builder.WriteString("if (Test-Path $Destination) {\n    robocopy $source $Destination *.zip /Z /FFT /XO\n}\n")
	builder.WriteString("Write-Host ('Manifest: ' + $manifest)\n")
	builder.WriteString("Write-Host 'Sync complete'\n")
	return builder.String()
}
func (g *generator) renderArchiveReadme(dept string, year int) string {
	builder := &strings.Builder{}
	fmt.Fprintf(builder, "%s %d export\n", titleCase(dept), year)
	builder.WriteString("-----------------------------------------\n\n")
	builder.WriteString("Contents:\n")
	builder.WriteString("- manifest.json: metadata for ingestion\n")
	builder.WriteString("- reports/: CSV summaries\n")
	builder.WriteString("- docs/checklist.yaml: validation checklist\n\n")
	builder.WriteString("This bundle was generated automatically for compliance review.\n")
	return builder.String()
}
func (g *generator) renderArchiveChecklist() string {
	builder := &strings.Builder{}
	builder.WriteString("checks:\n")
	builder.WriteString("  - name: Verify signature\n")
	builder.WriteString("    command: gpg --verify manifest.json.asc\n")
	builder.WriteString("  - name: Validate row counts\n")
	builder.WriteString("    command: python scripts/validate_rows.py\n")
	builder.WriteString("  - name: Confirm retention policy\n")
	builder.WriteString("    required: true\n")
	return builder.String()
}
func (g *generator) renderBackupManifestJSON(dept string, year int) []byte {
	manifest := map[string]interface{}{
		"department": titleCase(dept),
		"generated":  time.Now().Format(time.RFC3339),
		"year":       year,
		"owner":      g.pick(attendees),
		"files": []map[string]interface{}{
			{"path": "reports/summary.csv", "type": "csv"},
			{"path": "docs/checklist.yaml", "type": "yaml"},
		},
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return []byte("{}\n")
	}
	return append(data, '\n')
}
func (g *generator) renderBackupInventory() []byte {
	items := []map[string]interface{}{}
	for i := 0; i < 4; i++ {
		dept := g.randomDepartment()
		items = append(items, map[string]interface{}{
			"name":     fmt.Sprintf("%s-export", slugify(dept)),
			"owner":    g.pick(attendees),
			"size":     40 + g.rnd.Intn(120),
			"checksum": fmt.Sprintf("%x", g.rnd.Uint64()),
		})
	}
	payload := map[string]interface{}{
		"updated_at": time.Now().Format(time.RFC3339),
		"archives":   items,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return []byte("{}\n")
	}
	return append(data, '\n')
}
func renderBashScript(description string, commands []string) string {
	builder := &strings.Builder{}
	builder.WriteString("#!/bin/bash\n")
	builder.WriteString("set -euo pipefail\n\n")
	if description != "" {
		builder.WriteString("# ")
		builder.WriteString(description)
		builder.WriteString("\n\n")
	}
	for _, cmd := range commands {
		builder.WriteString(cmd)
		builder.WriteByte('\n')
	}
	return builder.String()
}
func (g *generator) renderEtcHosts(host, domain string) string {
	builder := &strings.Builder{}
	builder.WriteString("127.0.0.1\tlocalhost\n")
	builder.WriteString("255.255.255.255\tbroadcasthost\n")
	builder.WriteString("::1\tlocalhost\n")
	builder.WriteString("fe80::1%lo0\tlocalhost\n\n")
	fmt.Fprintf(builder, "10.%d.%d.%d\t%s.%s %s\n", 10+g.rnd.Intn(50), g.rnd.Intn(200), g.rnd.Intn(200), host, domain, host)
	fmt.Fprintf(builder, "10.%d.%d.%d\tfiles.%s\n", 20+g.rnd.Intn(30), g.rnd.Intn(200), g.rnd.Intn(200), domain)
	fmt.Fprintf(builder, "10.%d.%d.%d\tdb.%s\n", 30+g.rnd.Intn(20), g.rnd.Intn(200), g.rnd.Intn(200), domain)
	return builder.String()
}
func (g *generator) renderFstabFile() string {
	builder := &strings.Builder{}
	builder.WriteString("# <file system>\t<dir>\ttype\toptions\tdump\tpass\n")
	fmt.Fprintf(builder, "UUID=%08x-%04x-%04x-%04x-%012x / ext4 defaults 0 1\n", g.rnd.Uint32(), g.rnd.Uint32(), g.rnd.Uint32(), g.rnd.Uint32(), g.rnd.Uint64())
	fmt.Fprintf(builder, "UUID=%08x-%04x-%04x-%04x-%012x /var ext4 noatime 0 2\n", g.rnd.Uint32(), g.rnd.Uint32(), g.rnd.Uint32(), g.rnd.Uint32(), g.rnd.Uint64())
	builder.WriteString("tmpfs\t/tmp\ttmpfs\tdefaults,noatime,size=2048m 0 0\n")
	fmt.Fprintf(builder, "10.%d.%d.%d:/backups\t/mnt/backups\tnfs\trw,_netdev,hard,intr 0 0\n", 30+g.rnd.Intn(20), g.rnd.Intn(200), g.rnd.Intn(200))
	return builder.String()
}
func (g *generator) renderOSRelease() string {
	builder := &strings.Builder{}
	builder.WriteString("NAME=\"Acme Secure Linux\"\n")
	fmt.Fprintf(builder, "VERSION=\"%d.%d (Orion)\"\n", 1+g.rnd.Intn(2), 20+g.rnd.Intn(4))
	builder.WriteString("ID=acme\n")
	builder.WriteString("ID_LIKE=debian\n")
	builder.WriteString("PRETTY_NAME=\"Acme Secure Linux\"\n")
	builder.WriteString("HOME_URL=\"https://intranet." + g.randomInternalDomain() + "\"\n")
	return builder.String()
}
func (g *generator) renderSSHDConfig() string {
	port := 2200 + g.rnd.Intn(300)
	builder := &strings.Builder{}
	fmt.Fprintf(builder, "Port %d\n", port)
	builder.WriteString("Protocol 2\n")
	builder.WriteString("PermitRootLogin no\n")
	builder.WriteString("PasswordAuthentication yes\n")
	builder.WriteString("ChallengeResponseAuthentication no\n")
	builder.WriteString("UsePAM yes\n")
	builder.WriteString("X11Forwarding no\n")
	builder.WriteString("ClientAliveInterval 120\n")
	builder.WriteString("MaxAuthTries 3\n")
	builder.WriteString("Subsystem sftp /usr/libexec/sftp-server\n")
	return builder.String()
}
func (g *generator) renderNginxConfig(domain string) string {
	upstream := fmt.Sprintf("backend_%s", strings.ReplaceAll(domain, ".", "_"))
	builder := &strings.Builder{}
	builder.WriteString("worker_processes  2;\n")
	builder.WriteString("events { worker_connections  1024; }\n\n")
	fmt.Fprintf(builder, "upstream %s {\n", upstream)
	for i := 0; i < 3; i++ {
		fmt.Fprintf(builder, "    server 10.%d.%d.%d:8080 max_fails=3 fail_timeout=30s;\n", 40+g.rnd.Intn(20), g.rnd.Intn(200), g.rnd.Intn(200))
	}
	builder.WriteString("}\n\nserver {\n")
	builder.WriteString("    listen 443 ssl;\n")
	fmt.Fprintf(builder, "    server_name %s %s;\n", domain, "api."+domain)
	builder.WriteString("    ssl_certificate /etc/ssl/certs/acme.pem;\n")
	builder.WriteString("    ssl_certificate_key /etc/ssl/private/acme.key;\n")
	builder.WriteString("    access_log /var/log/nginx-access.log combined;\n")
	builder.WriteString("    location / { proxy_pass http://" + upstream + "; proxy_set_header Host $host; }\n")
	builder.WriteString("}\n")
	return builder.String()
}
func (g *generator) renderSystemdService(name, execPath, description string) string {
	builder := &strings.Builder{}
	fmt.Fprintf(builder, "[Unit]\nDescription=%s\nAfter=network.target\n\n", description)
	builder.WriteString("[Service]\n")
	builder.WriteString("Type=simple\nUser=svc-acme\n")
	fmt.Fprintf(builder, "ExecStart=%s --config /opt/acme/etc/agent.conf\n", execPath)
	builder.WriteString("Restart=on-failure\n")
	fmt.Fprintf(builder, "Environment=ACME_DOMAIN=%s\n", g.randomInternalDomain())
	builder.WriteString("[Install]\nWantedBy=multi-user.target\n")
	return builder.String()
}
func (g *generator) renderSystemdTimer(name string) string {
	builder := &strings.Builder{}
	fmt.Fprintf(builder, "[Unit]\nDescription=Schedule %s agent refresh\n\n", name)
	builder.WriteString("[Timer]\nOnCalendar=*-*-* 02:30:00\nPersistent=true\n")
	fmt.Fprintf(builder, "Unit=%s.service\n\n", name)
	builder.WriteString("[Install]\nWantedBy=timers.target\n")
	return builder.String()
}
func (g *generator) renderCronJob(name string) string {
	return fmt.Sprintf("15 3 * * * root /usr/bin/systemctl start %s.service >/var/log/%s-cron.log 2>&1\n", name, name)
}
func (g *generator) renderAuditYAML() string {
	builder := &strings.Builder{}
	builder.WriteString("rules:\n")
	builder.WriteString("  - id: sshd-config\n")
	builder.WriteString("    path: /etc/ssh/sshd_config\n")
	builder.WriteString("    notify: security@" + g.randomInternalDomain() + "\n")
	builder.WriteString("  - id: sudoers-change\n")
	builder.WriteString("    path: /etc/sudoers.d\n")
	builder.WriteString("    recursive: true\n")
	builder.WriteString("    critical: true\n")
	builder.WriteString("  - id: launchd-updates\n")
	builder.WriteString("    path: /Library/LaunchAgents\n")
	builder.WriteString("    recursive: true\n")
	builder.WriteString("    owner: root\n")
	return builder.String()
}
func (g *generator) renderProfileScript(domain string) string {
	commands := []string{
		"export PATH=/opt/acme/bin:$PATH",
		"export ACME_DOMAIN=" + domain,
		"export PROMPT_COMMAND='history -a'",
	}
	return renderBashScript("Developer profile additions", commands)
}
func (g *generator) renderPathsFile() string {
	return "/opt/acme/bin\n/usr/local/sbin\n"
}
func (g *generator) renderSudoersFile() string {
	return "devops ALL=(ALL) NOPASSWD: /usr/bin/systemctl start *.service, /usr/local/bin/backup-sync.sh\n"
}
func (g *generator) renderEnvironmentFile(domain string) string {
	builder := &strings.Builder{}
	builder.WriteString("ACME_DOMAIN=")
	builder.WriteString(domain)
	builder.WriteByte('\n')
	builder.WriteString("PATH=/usr/local/bin:/usr/bin:/bin:/opt/acme/bin\n")
	return builder.String()
}
func (g *generator) renderSystemShellScript(agentName, domain string) string {
	commands := []string{
		"log() { echo \"$(date '+%Y-%m-%d %H:%M:%S') $1\"; }",
		"log 'Triggering service refresh'",
		fmt.Sprintf("systemctl stop %s.service", agentName),
		"sleep 2",
		fmt.Sprintf("systemctl start %s.service", agentName),
		fmt.Sprintf("curl -sf https://status.%s/health || log 'health check failed'", domain),
	}
	return renderBashScript("Runtime refresh helper", commands)
}
func (g *generator) renderCleanupPythonScript(domain string) string {
	builder := &strings.Builder{}
	builder.WriteString("#!/usr/bin/env python3\n")
	builder.WriteString("import pathlib\nimport shutil\n\n")
	builder.WriteString("CACHE = pathlib.Path('/var/tmp/acme-cache')\n")
	builder.WriteString("if CACHE.exists():\n")
	builder.WriteString("    shutil.rmtree(CACHE)\n")
	builder.WriteString("CACHE.mkdir(parents=True, exist_ok=True)\n")
	builder.WriteString("(CACHE / 'origin.txt').write_text('refreshed for " + domain + "')\n")
	builder.WriteString("print('cache cleared')\n")
	return builder.String()
}
func (g *generator) renderUnixAgentConfig(agentName, domain string) []byte {
	payload := map[string]interface{}{
		"service": agentName,
		"domain":  domain,
		"endpoints": []string{
			"https://" + domain + "/ingest",
			"https://backup." + domain + "/ingest",
		},
		"interval_seconds": 300,
		"tls": map[string]interface{}{
			"ca_file":     "/etc/ssl/certs/ca-bundle.crt",
			"verify_peer": true,
		},
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return []byte("{}\n")
	}
	return append(data, '\n')
}
func (g *generator) renderUnixFeatureFlagsFile() string {
	builder := &strings.Builder{}
	builder.WriteString("flags:\n")
	for i := 0; i < min(6, len(featureFlags)); i++ {
		flag := featureFlags[i%len(featureFlags)]
		fmt.Fprintf(builder, "  %s: %t\n", flag, g.rnd.Intn(3) != 0)
	}
	builder.WriteString("rollouts:\n")
	builder.WriteString("  - cohort: beta\n    percentage: 25\n")
	builder.WriteString("  - cohort: production\n    percentage: 5\n")
	return builder.String()
}
func (g *generator) renderManifestYAML(agentName string) string {
	builder := &strings.Builder{}
	builder.WriteString("agent:\n")
	fmt.Fprintf(builder, "  name: %s\n", agentName)
	builder.WriteString("  version: 5.2.1\n")
	builder.WriteString("  checksum: ")
	builder.WriteString(fmt.Sprintf("%x\n", g.rnd.Uint64()))
	builder.WriteString("artifacts:\n")
	builder.WriteString("  - path: bin/agent\n    mode: 755\n")
	builder.WriteString("  - path: etc/agent.conf\n    mode: 644\n")
	return builder.String()
}
func (g *generator) renderDashboardJSON(domain string) []byte {
	payload := map[string]interface{}{
		"title": "Service Availability",
		"panels": []map[string]interface{}{
			{"type": "graph", "metric": "uptime", "target": domain},
			{"type": "stat", "metric": "error_rate", "threshold": 0.02},
		},
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return []byte("{}\n")
	}
	return append(data, '\n')
}
func (g *generator) renderLaunchAgentPlist(label, program string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>--once</string>
    </array>
    <key>StartInterval</key>
    <integer>900</integer>
</dict>
</plist>
`, label, program)
}
func (g *generator) renderPreferencesPlist(identifier, domain string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Identifier</key>
    <string>%s</string>
    <key>LastSyncedDomain</key>
    <string>%s</string>
    <key>TelemetryEnabled</key>
    <true/>
</dict>
</plist>
`, identifier, domain)
}
func (g *generator) renderLaunchDaemonPlist(label, exec string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>--daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
`, label, exec)
}
func (g *generator) randomBinaryHeader() []byte {
	headers := [][]byte{
		{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01},
		{0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01},
		{'M', 'Z', 0x90, 0x00},
	}
	choice := g.rnd.Intn(len(headers))
	return append([]byte{}, headers[choice]...)
}
func machOHeader() []byte {
	return []byte{0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00}
}
func (g *generator) writeBinaryFile(path string, minSize int, header []byte, mode os.FileMode) error {
	size := max(minSize, g.randomSize())
	if size < len(header)+512 {
		size = len(header) + 512 + g.rnd.Intn(1024)
	}
	data := make([]byte, size)
	copy(data, header)
	if _, err := g.rnd.Read(data[len(header):]); err != nil {
		return fmt.Errorf("generate binary: %w", err)
	}
	if mode == 0 {
		mode = 0o644
	}
	return os.WriteFile(path, data, mode)
}
func (g *generator) writeSystemBackupTar(path, agentName, domain string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	gz := gzip.NewWriter(file)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	entries := map[string][]byte{
		"README.txt":               []byte("Backup snapshot for " + agentName + "\n"),
		"etc/agent.conf":           []byte(g.renderAgentConf(agentName, domain)),
		"usr/local/etc/agent.json": g.renderUnixAgentConfig(agentName, domain),
	}
	now := time.Now()
	for name, body := range entries {
		hdr := &tar.Header{
			Name:    name,
			Mode:    0o644,
			Size:    int64(len(body)),
			ModTime: now,
		}
		if strings.HasSuffix(name, ".sh") {
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(body); err != nil {
			return err
		}
	}
	return nil
}
func (g *generator) renderPasswdBackup() string {
	builder := &strings.Builder{}
	builder.WriteString("root:x:0:0:System Administrator:/var/root:/bin/sh\n")
	builder.WriteString("daemon:*:1:1:System Services:/var/root:/usr/bin/false\n")
	builder.WriteString("svc-acme:*:501:501:Acme Agent:/var/acme:/bin/bash\n")
	return builder.String()
}
func (g *generator) renderSystemLog(host string) string {
	lines := make([]string, 0, 20)
	base := time.Now().Add(-6 * time.Hour)
	for i := 0; i < 18; i++ {
		ts := base.Add(time.Duration(i*20+g.rnd.Intn(10)) * time.Minute)
		process := g.pick(unixLogProcesses)
		message := g.pick(unixLogMessages)
		lines = append(lines, fmt.Sprintf("%s %s %s[%d]: %s", ts.Format("Jan _2 15:04:05"), host, process, 100+g.rnd.Intn(800), message))
	}
	return strings.Join(lines, "\n") + "\n"
}
func (g *generator) renderAuthLog(host string) string {
	lines := make([]string, 0, 16)
	base := time.Now().Add(-12 * time.Hour)
	for i := 0; i < 14; i++ {
		ts := base.Add(time.Duration(i*15+g.rnd.Intn(5)) * time.Minute)
		user := g.pick(unixAuthUsers)
		action := g.pick(unixAuthEvents)
		lines = append(lines, fmt.Sprintf("%s %s sshd[%d]: %s for %s from 10.%d.%d.%d port %d ssh2", ts.Format("Jan _2 15:04:05"), host, 400+g.rnd.Intn(500), action, user, 10+g.rnd.Intn(20), g.rnd.Intn(200), g.rnd.Intn(200), 40000+g.rnd.Intn(2000)))
	}
	return strings.Join(lines, "\n") + "\n"
}
func (g *generator) renderAccessLog(domain string) string {
	lines := make([]string, 0, 12)
	base := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 12; i++ {
		ts := base.Add(time.Duration(i*5) * time.Minute)
		verb := g.pick(httpVerbs)
		path := g.pick(httpPaths)
		status := g.pick(httpStatuses)
		ua := g.pick(userAgents)
		lines = append(lines, fmt.Sprintf("%s - - [%s] \"%s %s HTTP/1.1\" %s %d \"-\" \"%s\"", domain, ts.Format("02/Jan/2006:15:04:05 -0700"), verb, path, status, 2000+g.rnd.Intn(6000), ua))
	}
	return strings.Join(lines, "\n") + "\n"
}
func (g *generator) renderDeployLock(agentName string) string {
	builder := &strings.Builder{}
	builder.WriteString("locked_by=deploy@")
	builder.WriteString(g.randomInternalDomain())
	builder.WriteByte('\n')
	fmt.Fprintf(builder, "service=%s\n", agentName)
	fmt.Fprintf(builder, "timestamp=%s\n", time.Now().Format(time.RFC3339))
	return builder.String()
}
func (g *generator) renderAgentConf(agentName, domain string) string {
	builder := &strings.Builder{}
	fmt.Fprintf(builder, "[agent]\nname=%s\ndomain=%s\n", agentName, domain)
	builder.WriteString("[logging]\nlevel=info\nfile=/var/log/" + agentName + ".log\n")
	builder.WriteString("[metrics]\ninterval=60\n")
	return builder.String()
}
func (g *generator) renderKeystore() []byte {
	payload := map[string]string{
		"api_key":       fmt.Sprintf("%032x", g.rnd.Uint64()<<32|uint64(g.rnd.Uint32())),
		"client_secret": fmt.Sprintf("%032x", g.rnd.Uint64()<<32|uint64(g.rnd.Uint32())),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return []byte("{}\n")
	}
	return append(data, '\n')
}
func (g *generator) renderInstallerLog() string {
	lines := []string{
		fmt.Sprintf("%s Installer[1234]: Package Authoring Tool", time.Now().Add(-90*time.Minute).Format(time.RFC3339)),
		fmt.Sprintf("%s installd[123]: Installed com.acme.agent", time.Now().Add(-80*time.Minute).Format(time.RFC3339)),
		fmt.Sprintf("%s system_installd[98]: Launching postinstall", time.Now().Add(-75*time.Minute).Format(time.RFC3339)),
		fmt.Sprintf("%s acme-agent[345]: registration complete", time.Now().Add(-74*time.Minute).Format(time.RFC3339)),
	}
	return strings.Join(lines, "\n") + "\n"
}
func (g *generator) renderUpdateStatus(domain string) []byte {
	payload := map[string]interface{}{
		"version":      fmt.Sprintf("%d.%d.%d", 5, 2, g.rnd.Intn(10)),
		"state":        "installed",
		"last_contact": time.Now().Add(-15 * time.Minute).Format(time.RFC3339),
		"mirror":       "https://updates." + domain,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return []byte("{}\n")
	}
	return append(data, '\n')
}
func (g *generator) renderMaintenanceReadme(agentName string) string {
	builder := &strings.Builder{}
	builder.WriteString("Maintenance Checklist\n======================\n\n")
	builder.WriteString("1. Run /usr/local/bin/backup-sync.sh\n")
	builder.WriteString("2. Verify systemctl status " + agentName + ".service\n")
	builder.WriteString("3. Confirm /var/backups contains latest snapshot\n")
	return builder.String()
}
func (g *generator) generateUnixReadme(host, domain, agentName string) error {
	lines := []string{
		"# Synthetic Unix Root Layout",
		"",
		"This dataset mirrors the top-level structure of a macOS/Linux volume for testing.",
		"It includes system services, logs, launchd/systemd units, configuration files,",
		"and placeholder binaries so encryption policies can be rehearsed safely.",
		"",
		"## Highlights",
		fmt.Sprintf("- Hostname: %s", host),
		fmt.Sprintf("- Primary domain: %s", domain),
		fmt.Sprintf("- Managed service: %s", agentName),
		"- /etc holds sshd, nginx, cron, and audit policy samples",
		"- /usr/local/bin contains maintenance scripts (shell + Python)",
		"- /var/log includes auth/system/access logs for playback",
		"- /opt/acme mimics a third-party agent with binaries and config",
		"- Library/System/Library contain launchd metadata for macOS",
		"",
		fmt.Sprintf("Generated: %s", time.Now().Format(time.RFC3339)),
	}
	return os.WriteFile(filepath.Join(g.cfg.OutDir, "README.md"), []byte(strings.Join(lines, "\n")), 0o644)
}
func (g *generator) randomDepartment() string {
	return g.pick(departments)
}
func (g *generator) randomCampaignName() string {
	color := titleCase(g.pick(colors))
	theme := titleCase(g.pick(campaignThemes))
	return fmt.Sprintf("%s %s", color, theme)
}
func (g *generator) randomRecentDate() time.Time {
	days := g.rnd.Intn(365)
	return time.Now().AddDate(0, 0, -days)
}
func (g *generator) randomAttendees() []string {
	count := 3 + g.rnd.Intn(4)
	shuffled := append([]string{}, attendees...)
	g.rnd.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	return shuffled[:count]
}
func (g *generator) renderBudgetRows() string {
	headers := []string{"Department", "Owner", "Q1", "Q2", "Q3", "Q4", "Total"}
	rows := [][]string{headers}
	deptCount := 4 + g.rnd.Intn(4)
	used := map[string]bool{}
	for i := 0; i < deptCount; i++ {
		dept := titleCase(g.randomDepartment())
		if used[dept] {
			i--
			continue
		}
		used[dept] = true
		owner := g.pick(attendees)
		q := [4]float64{}
		total := 0.0
		for idx := 0; idx < 4; idx++ {
			base := 75000 + g.rnd.Float64()*85000
			q[idx] = math.Round(base*100) / 100
			total += q[idx]
		}
		row := []string{dept, owner}
		for _, val := range q {
			row = append(row, fmt.Sprintf("%.2f", val))
		}
		row = append(row, fmt.Sprintf("%.2f", total))
		rows = append(rows, row)
	}
	var buf strings.Builder
	for _, row := range rows {
		buf.WriteString(strings.Join(row, ","))
		buf.WriteByte('\n')
	}
	return buf.String()
}
func (g *generator) generateParagraphs(targetBytes, minWords, maxWords int) []string {
	paragraphs := []string{}
	total := 0
	for total < targetBytes {
		wordCount := minWords + g.rnd.Intn(maxWords-minWords+1)
		paragraphs = append(paragraphs, g.randomParagraph(wordCount))
		total += len(paragraphs[len(paragraphs)-1])
	}
	return paragraphs
}
func (g *generator) randomParagraph(words int) string {
	sentences := []string{}
	usedWords := 0
	for usedWords < words {
		sentence := g.randomSentence()
		wordCount := len(strings.Fields(sentence))
		sentences = append(sentences, sentence)
		usedWords += wordCount
	}
	return strings.Join(sentences, " ")
}
func (g *generator) randomSentence() string {
	template := sentenceTemplates[g.rnd.Intn(len(sentenceTemplates))]
	var builder strings.Builder
	remaining := template
	for {
		start := strings.Index(remaining, "{{")
		if start == -1 {
			builder.WriteString(remaining)
			break
		}
		builder.WriteString(remaining[:start])
		end := strings.Index(remaining[start:], "}}")
		if end == -1 {
			builder.WriteString(remaining[start:])
			break
		}
		token := remaining[start+2 : start+end]
		builder.WriteString(g.resolveToken(token))
		remaining = remaining[start+end+2:]
	}
	sentence := strings.TrimSpace(builder.String())
	if sentence == "" {
		sentence = strings.TrimSpace(template)
	}
	if !strings.HasSuffix(sentence, ".") && !strings.HasSuffix(sentence, "!") && !strings.HasSuffix(sentence, "?") {
		sentence += "."
	}
	return sentence
}
func (g *generator) resolveToken(token string) string {
	switch token {
	case "dept":
		return titleCase(g.pick(departments))
	case "verb":
		return g.pick(verbs)
	case "noun":
		return g.pick(nouns)
	case "metric":
		return g.pick(metrics)
	case "initiative":
		return g.pick(initiatives)
	case "adjective":
		return g.pick(adjectives)
	case "result":
		return g.pick(results)
	case "risk":
		return g.pick(risks)
	default:
		return g.pick(nouns)
	}
}
func (g *generator) pick(values []string) string {
	return values[g.rnd.Intn(len(values))]
}
func slugify(title string) string {
	title = strings.ToLower(title)
	var buf strings.Builder
	buf.Grow(len(title))
	lastHyphen := false
	for _, r := range title {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			buf.WriteRune(r)
			lastHyphen = false
			continue
		}
		if r == ' ' || r == '-' || r == '_' {
			if !lastHyphen && buf.Len() > 0 {
				buf.WriteByte('-')
				lastHyphen = true
			}
		}
	}
	result := buf.String()
	result = strings.Trim(result, "-")
	if result == "" {
		result = fmt.Sprintf("file-%d", time.Now().UnixNano())
	}
	return result
}
func titleCase(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	words := strings.Fields(value)
	for i, word := range words {
		words[i] = titleCaseWord(word)
	}
	return strings.Join(words, " ")
}
func titleCaseWord(word string) string {
	parts := strings.Split(word, "-")
	for i, part := range parts {
		lower := strings.ToLower(part)
		if lower == "" {
			continue
		}
		parts[i] = strings.ToUpper(lower[:1]) + lower[1:]
	}
	return strings.Join(parts, "-")
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
// --- Archive helpers ---
type zipEntry struct {
	Name string
	Body []byte
	Mode os.FileMode
}
func writeZipArchive(path string, entries []zipEntry) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	zw := zip.NewWriter(file)
	defer zw.Close()
	now := time.Now()
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.Name, Method: zip.Deflate}
		header.SetModTime(now)
		if entry.Mode != 0 {
			header.SetMode(entry.Mode)
		} else {
			header.SetMode(0o644)
		}
		writer, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err := writer.Write(entry.Body); err != nil {
			return err
		}
	}
	return nil
}
// --- Document helpers ---
type docxText struct {
	XMLName xml.Name `xml:"w:t"`
	Text    string   `xml:",chardata"`
}
type docxRun struct {
	XMLName xml.Name `xml:"w:r"`
	Text    docxText `xml:"w:t"`
}
type docxParagraph struct {
	XMLName xml.Name  `xml:"w:p"`
	Runs    []docxRun `xml:"w:r"`
}
type docxBody struct {
	XMLName    xml.Name        `xml:"w:body"`
	Paragraphs []docxParagraph `xml:"w:p"`
	Section    *struct{}       `xml:"w:sectPr"`
}
type docxDocument struct {
	XMLName xml.Name `xml:"w:document"`
	Xmlns   string   `xml:"xmlns:w,attr"`
	Body    docxBody `xml:"w:body"`
}
func writeDocx(path, title string, paragraphs []string) (err error) {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	zw := zip.NewWriter(file)
	defer func() {
		closeErr := zw.Close()
		if err == nil {
			err = closeErr
		}
	}()
	add := func(name string, data []byte) error {
		w, createErr := zw.Create(name)
		if createErr != nil {
			return createErr
		}
		_, writeErr := w.Write(data)
		return writeErr
	}
	doc := docxDocument{
		Xmlns: "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
		Body:  docxBody{Section: &struct{}{}},
	}
	doc.Body.Paragraphs = append(doc.Body.Paragraphs, makeParagraph(title))
	for _, para := range paragraphs {
		doc.Body.Paragraphs = append(doc.Body.Paragraphs, makeParagraph(para))
	}
	bodyBytes, err := xml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal document: %w", err)
	}
	bodyBytes = append([]byte(xml.Header), bodyBytes...)
	contentTypes := `<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
    <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
    <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
    <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>`
	rels := `<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
    <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
    <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>`
	timestamp := time.Now().UTC().Format(time.RFC3339)
	core := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <dc:title>%s</dc:title>
    <dc:creator>File Crypto Generator</dc:creator>
    <cp:lastModifiedBy>File Crypto Generator</cp:lastModifiedBy>
    <dcterms:created xsi:type="dcterms:W3CDTF">%s</dcterms:created>
    <dcterms:modified xsi:type="dcterms:W3CDTF">%s</dcterms:modified>
</cp:coreProperties>`, xmlEscape(title), timestamp, timestamp)
	app := `<?xml version="1.0" encoding="UTF-8"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
    <Application>File Crypto Test Data Generator</Application>
    <Pages>1</Pages>
    <Words>750</Words>
</Properties>`
	styles := `<?xml version="1.0" encoding="UTF-8"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal">
    <w:name w:val="Normal"/>
    <w:qFormat/>
  </w:style>
</w:styles>`
	if err := add("[Content_Types].xml", []byte(contentTypes)); err != nil {
		return err
	}
	if err := add("_rels/.rels", []byte(rels)); err != nil {
		return err
	}
	if err := add("docProps/core.xml", []byte(core)); err != nil {
		return err
	}
	if err := add("docProps/app.xml", []byte(app)); err != nil {
		return err
	}
	if err := add("word/document.xml", bodyBytes); err != nil {
		return err
	}
	if err := add("word/_rels/document.xml.rels", []byte(`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>`)); err != nil {
		return err
	}
	if err := add("word/styles.xml", []byte(styles)); err != nil {
		return err
	}
	return nil
}
func makeParagraph(text string) docxParagraph {
	return docxParagraph{Runs: []docxRun{{Text: docxText{Text: text}}}}
}
func xmlEscape(value string) string {
	var buf bytes.Buffer
	xml.EscapeText(&buf, []byte(value))
	return buf.String()
}
func renderRTF(title string, paragraphs []string) string {
	escaped := func(s string) string {
		replacer := strings.NewReplacer("\\", "\\\\", "{", "\\{", "}", "\\}")
		return replacer.Replace(s)
	}
	var buf strings.Builder
	buf.WriteString("{\\rtf1\\ansi\\deff0\\pard\\sa200\\sl276\\slmult1\n")
	buf.WriteString("{\\b ")
	buf.WriteString(escaped(title))
	buf.WriteString("}\\par\n")
	for _, para := range paragraphs {
		buf.WriteString(escaped(para))
		buf.WriteString("\\par\n")
	}
	buf.WriteString("}")
	return buf.String()
}
// --- PDF helpers ---
func writePDF(path, title string, paragraphs []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	var lines []string
	lines = append(lines, fmt.Sprintf("%s", title))
	for _, para := range paragraphs {
		lines = append(lines, wrapTextForPDF(para, 90)...)
		lines = append(lines, "")
	}
	content := &strings.Builder{}
	content.WriteString("BT\n/F1 16 Tf\n72 760 Td\n")
	first := true
	for _, line := range lines {
		if !first {
			content.WriteString("0 -18 Td\n")
		}
		first = false
		if line == "" {
			content.WriteString("0 -12 Td\n")
			continue
		}
		text := escapePDFString(line)
		content.WriteString(fmt.Sprintf("(%s) Tj\n", text))
	}
	content.WriteString("ET\n")
	contentBytes := []byte(content.String())
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(contentBytes), contentBytes),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		fmt.Sprintf("<< /Producer (File Crypto Test Data Generator) /Title (%s) >>", escapePDFString(title)),
	}
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")
	offsets := make([]int, len(objects)+1)
	for i, obj := range objects {
		offsets[i+1] = buf.Len()
		buf.WriteString(fmt.Sprintf("%d 0 obj\n%s\nendobj\n", i+1, obj))
	}
	xrefPos := buf.Len()
	buf.WriteString(fmt.Sprintf("xref\n0 %d\n", len(objects)+1))
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= len(objects); i++ {
		buf.WriteString(fmt.Sprintf("%010d 00000 n \n", offsets[i]))
	}
	buf.WriteString("trailer\n")
	buf.WriteString(fmt.Sprintf("<< /Size %d /Root 1 0 R /Info 6 0 R >>\n", len(objects)+1))
	buf.WriteString(fmt.Sprintf("startxref\n%d\n%%%%EOF\n", xrefPos))
	_, err = file.Write(buf.Bytes())
	return err
}
func wrapTextForPDF(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	lines := []string{}
	current := words[0]
	for _, word := range words[1:] {
		if len(current)+1+len(word) > width {
			lines = append(lines, current)
			current = word
			continue
		}
		current += " " + word
	}
	lines = append(lines, current)
	return lines
}
func escapePDFString(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "(", "\\(", ")", "\\)")
	return replacer.Replace(value)
}
// --- PNG helpers ---
func writeMarketingPNG(path string, target int, rnd *rand.Rand) error {
	pixels := max(target/3, 40000)
	side := int(math.Sqrt(float64(pixels)))
	width := clamp(side, 320, 1024)
	height := clamp(pixels/width, 200, 768)
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	baseColor := color.RGBA{uint8(rnd.Intn(90) + 40), uint8(rnd.Intn(90) + 80), uint8(rnd.Intn(90) + 80), 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{baseColor}, image.Point{}, draw.Src)
	stripeColor := color.RGBA{uint8(200 + rnd.Intn(55)), uint8(120 + rnd.Intn(80)), uint8(rnd.Intn(120)), 255}
	stripeWidth := max(20, width/15)
	for x := -stripeWidth; x < width+stripeWidth; x += stripeWidth * 2 {
		for y := 0; y < height; y++ {
			for dx := 0; dx < stripeWidth && x+dx < width; dx++ {
				xx := x + dx
				if xx >= 0 && (xx+y)%3 == 0 {
					img.Set(xx, y, stripeColor)
				}
			}
		}
	}
	dots := width * height / 120
	accent := color.RGBA{uint8(240 - rnd.Intn(50)), uint8(240 - rnd.Intn(50)), uint8(240 - rnd.Intn(50)), 255}
	for i := 0; i < dots; i++ {
		x := rnd.Intn(width)
		y := rnd.Intn(height)
		img.Set(x, y, accent)
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := png.Encoder{CompressionLevel: png.BestCompression}
	return encoder.Encode(file, img)
}
func clamp(value, minVal, maxVal int) int {
	if value < minVal {
		return minVal
	}
	if value > maxVal {
		return maxVal
	}
	return value
}
// --- Data tables ---
var (
	quarters     = []string{"Q1", "Q2", "Q3", "Q4"}
	reportTopics = []string{"operations", "revenue", "compliance", "product", "talent", "security", "customer"}
	reportFocus  = []string{"brief", "update", "review", "outlook", "report"}
	policyAdjectives = []string{"global", "comprehensive", "interim", "supplemental", "updated", "mandatory"}
	policySubjects   = []string{"security", "travel", "device", "remote work", "expense", "privacy", "conduct"}
	policySuffixes   = []string{"guidelines", "policy", "standard", "handbook", "agreement"}
	summaryQualifiers = []string{"Executive", "Operational", "Strategic", "Board"}
	summarySubjects   = []string{"Performance", "Risk", "Revenue", "Program", "Initiative"}
	meetingPrefixes = []string{"Weekly", "Quarterly", "All-Hands", "Leadership", "Board", "Project"}
	departments = []string{"finance", "operations", "marketing", "engineering", "people", "customer success", "security", "it", "sales", "product"}
	colors         = []string{"amber", "crimson", "sage", "indigo", "coral", "slate", "violet", "cobalt", "teal", "golden"}
	campaignThemes = []string{"momentum", "horizon", "elevation", "insight", "compass", "signal", "alloy", "spectrum", "summit"}
	attendees = []string{"Jordan Li", "Priya Raman", "Alex Chen", "Maria Ortiz", "Samir Patel", "Fatima Alvi", "Noah Johnson", "Grace Muller", "Evelyn Price", "Mateo Silva"}
	actionItems = []string{"publish the finalized brief", "update the budget tracker", "deliver revised projections", "schedule stakeholder interviews", "review vendor compliance", "refresh the onboarding materials", "complete the SOC 2 gap analysis", "draft communication plan", "prepare rollout dashboard"}
	verbs       = []string{"accelerated", "completed", "implemented", "piloted", "evaluated", "benchmarked", "finalized", "updated", "calibrated"}
	nouns       = []string{"roadmap", "program", "initiative", "deployment", "pilot", "strategy", "dashboard", "playbook", "workflow", "analysis"}
	metrics     = []string{"customer retention", "operating margin", "deployment velocity", "incident response time", "support backlog", "infrastructure cost", "runway", "feature adoption"}
	initiatives = []string{"comms refresh", "risk assessment", "platform migration", "training plan", "automation suite", "client outreach"}
	adjectives  = []string{"cross-functional", "data-informed", "scalable", "measurable", "high-impact", "long-term", "cloud-native"}
	results     = []string{"measurable gains", "notable savings", "strong engagement", "steady growth", "reduced variance", "improved satisfaction"}
	risks       = []string{"regulatory exposure", "vendor slippage", "capacity constraints", "budget pressure", "talent churn"}
	applications    = []string{"atlas api", "compass portal", "horizon sync", "ledger ops", "pulse analytics", "relay gateway", "vector scheduler"}
	regions         = []string{"us-east-1", "us-west-2", "eu-central-1", "ap-southeast-2"}
	databaseEngines = []string{"postgres", "mysql", "aurora-postgresql"}
	featureFlags    = []string{"realtime-insights", "zero-touch-onboarding", "async-reporting", "metrics-v2", "autoscale-profiles", "activity-feed", "compliance-audit"}
	releaseCohorts  = []string{"beta", "internal", "early-access", "general"}
	internalDomains         = []string{"corp.acme.local", "ops.acme.internal", "lab.acme.lan", "hq.acme.example", "devnet.acme"}
	unixHostnames           = []string{"macmini-ops", "mbp-admin", "edge-cache", "vault-srv", "telemetry-node", "db-gateway"}
	unixServicePrefixes     = []string{"acme", "core", "metrics", "sync", "backup", "sensor", "telemetry"}
	unixServiceSuffixes     = []string{"agent", "bridge", "daemon", "collector", "relay", "watcher"}
	unixServiceDescriptions = []string{"Acme telemetry agent", "Scheduled backup collector", "Metrics forwarding service", "Endpoint sync orchestrator"}
	unixLogProcesses = []string{"launchd", "systemd", "acme-agent", "backupd", "mdworker", "configd", "cron"}
	unixLogMessages  = []string{"Started background sync job", "Completed snapshot rotation", "Pruned cache entries", "Health check reported success", "Reloaded configuration from disk", "Pending update detected"}
	unixAuthUsers    = []string{"admin", "deploy", "svc-acme", "ops", "root"}
	unixAuthEvents   = []string{"Accepted publickey", "Accepted password", "Failed password", "session opened", "session closed"}
	httpVerbs    = []string{"GET", "POST", "PUT", "DELETE"}
	httpPaths    = []string{"/api/status", "/api/health", "/sync", "/metrics", "/v1/export"}
	httpStatuses = []string{"200", "201", "204", "302", "401", "503"}
	userAgents   = []string{"curl/8.1.2", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "Go-http-client/2.0", "PostmanRuntime/7.37", "Python-urllib/3.11"}
	sentenceTemplates = []string{
		"The {{dept}} team {{verb}} the {{noun}} to bolster {{metric}}.",
		"We observed {{adjective}} momentum across the {{initiative}}, yielding {{result}}.",
		"Stakeholders flagged {{risk}}, prompting a {{noun}} redesign.",
		"Leadership requested a deeper dive on {{metric}} following the latest {{noun}}.",
		"A {{adjective}} {{initiative}} is underway to improve {{metric}}.",
	}
)
