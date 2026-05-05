package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"secrethunter/internal/ai"
	"secrethunter/internal/analyzer"
	"secrethunter/internal/models"
	"secrethunter/internal/reporter"
	"secrethunter/internal/scanner"
	"secrethunter/internal/validator"
)

type CLI struct {
	scanner    *scanner.Scanner
	aiEngine   *ai.AIEngine
	validator  *validator.Validator
	reporter   *reporter.Reporter
	results    []models.Finding
	config     *models.Config
	running    bool
	reader     *bufio.Reader
}

func NewCLI() *CLI {
	return &CLI{
		scanner:   scanner.NewScanner(),
		aiEngine:  ai.NewAIEngine(),
		validator: validator.NewValidator(),
		reporter:  reporter.NewReporter(),
		config:    models.DefaultConfig(),
		reader:    bufio.NewReader(os.Stdin),
	}
}

func (c *CLI) Run() {
	c.printBanner()

	for c.running {
		fmt.Print(c.color("SecretHunter> ", "cyan"))
		input, err := c.reader.ReadString('\n')
		if err != nil {
			break
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		c.handleCommand(input)
	}
}

func (c *CLI) handleCommand(input string) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "help", "?":
		c.printHelp()
	case "set":
		c.handleSet(args)
	case "scan":
		c.handleScan(args)
	case "analyze":
		c.handleAnalyze(args)
	case "validate":
		c.handleValidate(args)
	case "results":
		c.handleResults(args)
	case "status":
		c.handleStatus()
	case "clear":
		c.results = nil
		fmt.Println(c.color("Results cleared.", "green"))
	case "export":
		c.handleExport(args)
	case "rules":
		c.handleRules()
	case "report":
		c.handleReport(args)
	case "risk":
		c.handleReport(args)
	case "exit", "quit", "q":
		c.running = false
		fmt.Println(c.color("Goodbye!", "cyan"))
	default:
		fmt.Printf(c.color("Unknown command: %s\n", "red"), cmd)
		c.printHelp()
	}
}

func (c *CLI) printHelp() {
	help := `
╔═══════════════════════════════════════════════════════════════╗
║                      SecretHunter Commands                    ║
╠═══════════════════════════════════════════════════════════════╣
║  Configuration                                                ║
║    set openai <key>        - Set OpenAI API key              ║
║    set anthropic <key>     - Set Anthropic API key           ║
║    set ollama <model>      - Set Ollama model (e.g. llama3)  ║
║    set default-ai <name>   - Set default AI provider         ║
║                                                                     ║
║  Scanning                                                     ║
║    scan local <path>              - Scan local directory       ║
║    scan local <path> --exclude X  - Scan with exclusions       ║
║    scan github <url>               - Scan GitHub repo          ║
║    scan github <url> --exclude X - Scan with exclusions       ║
║    scan content <text>            - Scan raw text content      ║
║                                                                     ║
║  Analysis                                                     ║
║    analyze <id>            - Run AI analysis on finding       ║
║    analyze all             - Analyze all findings             ║
║    validate <id>           - Validate if key is valid (YOURS)║
║    validate all            - Validate all findings            ║
║                                                                     ║
║  Results                                                      ║
║    results                 - Show all findings                ║
║    results <id>            - Show specific finding detail   ║
║    results --table         - Show findings in table format    ║
║    results --json          - Show findings in JSON           ║
║    results --summary      - Show summary statistics          ║
║                                                                     ║
║  Export                                                       ║
║    export json <file>      - Export results to JSON          ║
║    export txt <file>       - Export results to text          ║
║                                                                     ║
║  Other                                                        ║
║    status                  - Show current configuration      ║
║    rules                  - Show available detection rules  ║
║    report                 - Generate detailed risk report   ║
║    clear                  - Clear current results           ║
║    help                   - Show this help                  ║
║    exit                   - Exit                             ║
╚═══════════════════════════════════════════════════════════════╝
`
	fmt.Println(c.color(help, "cyan"))
}

func (c *CLI) handleSet(args []string) {
	if len(args) < 2 {
		fmt.Println(c.color("Usage: set <provider> <key> [extra]", "red"))
		return
	}

	provider := strings.ToLower(args[0])
	key := args[1]

	switch provider {
	case "openai":
		c.config.OpenAIKey = key
		fmt.Println(c.color("OpenAI API key configured.", "green"))
	case "anthropic":
		c.config.AnthropicKey = key
		fmt.Println(c.color("Anthropic API key configured.", "green"))
	case "ollama":
		model := "llama3"
		url := "http://localhost:11434"
		if len(args) > 2 {
			model = args[2]
		}
		if len(args) > 3 {
			url = args[3]
		}
		c.config.OllamaURL = url
		c.config.OllamaModel = model
		fmt.Printf(c.color("Ollama configured: model=%s, url=%s\n", "green"), model, url)
	case "default-ai":
		c.config.DefaultAI = key
		fmt.Printf(c.color("Default AI set to: %s\n", "green"), key)
	default:
		fmt.Printf(c.color("Unknown provider: %s\n", "red"), provider)
	}

	c.aiEngine.SetConfig(c.config)
}

func (c *CLI) handleScan(args []string) {
	if len(args) < 2 {
		fmt.Println(c.color("Usage: scan <type> <path> [--exclude pattern]", "red"))
		return
	}

	scanType := strings.ToLower(args[0])
	target := args[1]

	var excludes []string
	for i := 2; i < len(args); i++ {
		if args[i] == "--exclude" && i+1 < len(args) {
			excludes = append(excludes, args[i+1])
			i++
		}
	}

	fmt.Println(c.color("Scanning...", "yellow"))
	if len(excludes) > 0 {
		fmt.Printf(c.color("  Excluding: %s\n", "dim"), strings.Join(excludes, ", "))
	}

	start := time.Now()

	var findings []models.Finding
	var err error

	switch scanType {
	case "local":
		absPath, err := filepath.Abs(target)
		if err != nil {
			fmt.Printf(c.color("Error resolving path: %v\n", "red"), err)
			return
		}
		findings, err = c.scanner.ScanPath(absPath, excludes...)
	case "github":
		cloneDir, err := c.cloneGitHubRepo(target)
		if err != nil {
			fmt.Printf(c.color("Error cloning repo: %v\n", "red"), err)
			return
		}
		findings, err = c.scanner.ScanPath(cloneDir, excludes...)
		os.RemoveAll(cloneDir)
		fmt.Println(c.color("  [Cleaned up cloned repository]", "dim"))
	case "content":
		findings = c.scanner.ScanContent(target)
	default:
		fmt.Printf(c.color("Unknown scan type: %s\n", "red"), scanType)
		return
	}

	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf(c.color("Scan error: %v\n", "red"), err)
		return
	}

	c.results = findings

	fmt.Printf(c.color("\nScan complete!\n", "green"))
	fmt.Printf("Found: %d potential secrets\n", len(findings))
	fmt.Printf("Time: %.2fs\n", elapsed.Seconds())

	if len(findings) > 0 && len(findings) <= 10 {
		fmt.Println()
		c.reporter.PrintFindings(findings)
	} else if len(findings) > 10 {
		fmt.Println()
		c.reporter.PrintTable(findings)
	}
}

func (c *CLI) cloneGitHubRepo(url string) (string, error) {
	parts := strings.Split(url, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid GitHub URL")
	}

	repo := parts[len(parts)-1]
	if strings.HasSuffix(repo, ".git") {
		repo = strings.TrimSuffix(repo, ".git")
	}

	tmpDir := filepath.Join(os.TempDir(), "secrethunter-"+repo)

	cmd := exec.Command("git", "clone", "--depth", "1", url, tmpDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", err
	}

	return tmpDir, nil
}

func (c *CLI) handleAnalyze(args []string) {
	if len(c.results) == 0 {
		fmt.Println(c.color("No results to analyze. Run 'scan' first.", "red"))
		return
	}

	if !c.isAIConfigured() {
		fmt.Println(c.color("No AI provider configured. Use 'set openai <key>' or 'set anthropic <key>'", "red"))
		return
	}

	if len(args) == 0 {
		fmt.Println(c.color("Usage: analyze <id> or analyze all", "red"))
		return
	}

	if args[0] == "all" {
		c.analyzeAll()
	} else {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Println(c.color("Invalid ID. Use 'results' to see IDs.", "red"))
			return
		}
		c.analyzeOne(id)
	}
}

func (c *CLI) analyzeAll() {
	fmt.Println(c.color("Analyzing all findings...", "yellow"))

	analyzed := 0
	for i := range c.results {
		fmt.Printf("\rAnalyzing: %d/%d", i+1, len(c.results))

		analysis, err := c.aiEngine.AnalyzeWithBestProvider(c.results[i])
		if err != nil {
			continue
		}

		c.results[i].AIAnalysis = analysis
		analyzed++
	}

	fmt.Printf("\n\nAnalyzed %d findings.\n", analyzed)
}

func (c *CLI) analyzeOne(id int) {
	if id < 1 || id > len(c.results) {
		fmt.Println(c.color("Invalid ID. Use 'results' to see IDs.", "red"))
		return
	}

	finding := c.results[id-1]
	fmt.Printf(c.color("\nAnalyzing finding #%d...\n", "yellow"), id)

	analysis, err := c.aiEngine.AnalyzeWithBestProvider(finding)
	if err != nil {
		fmt.Printf(c.color("Analysis error: %v\n", "red"), err)
		return
	}

	c.results[id-1].AIAnalysis = analysis
	c.reporter.PrintFindingDetail(finding)
}

func (c *CLI) handleValidate(args []string) {
	if len(c.results) == 0 {
		fmt.Println(c.color("No results to validate. Run 'scan' first.", "red"))
		return
	}

	fmt.Println(c.color("⚠️  Warning: Only validate keys that YOU own!", "magenta"))
	fmt.Println(c.color("    Validating others' keys is illegal.\n", "yellow"))

	if len(args) == 0 {
		fmt.Println(c.color("Usage: validate <id> or validate all", "red"))
		return
	}

	if args[0] == "all" {
		c.validateAll()
	} else {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Println(c.color("Invalid ID. Use 'results' to see IDs.", "red"))
			return
		}
		c.validateOne(id)
	}
}

func (c *CLI) validateAll() {
	validated := 0
	for i := range c.results {
		fmt.Printf("\rValidating: %d/%d", i+1, len(c.results))

		secretValue := extractSecretValue(c.results[i].Match)
		result := c.validator.Validate(c.results[i], secretValue)
		c.results[i].Validation = result
		if result.IsValid {
			validated++
		}
	}

	fmt.Printf("\n\nValidated %d/%d findings.\n", validated, len(c.results))
}

func (c *CLI) validateOne(id int) {
	if id < 1 || id > len(c.results) {
		fmt.Println(c.color("Invalid ID. Use 'results' to see IDs.", "red"))
		return
	}

	finding := c.results[id-1]
	fmt.Printf(c.color("\nValidating finding #%d...\n", "yellow"), id)

	secretValue := extractSecretValue(finding.Match)
	result := c.validator.Validate(finding, secretValue)

	c.results[id-1].Validation = result
	c.reporter.PrintFindingDetail(c.results[id-1])
}

func (c *CLI) handleResults(args []string) {
	if len(c.results) == 0 {
		fmt.Println(c.color("No results. Run 'scan' first.", "yellow"))
		return
	}

	if len(args) == 0 {
		c.reporter.PrintFindings(c.results)
		return
	}

	arg := args[0]

	if arg == "--table" {
		c.reporter.PrintTable(c.results)
	} else if arg == "--json" {
		json, err := c.reporter.ExportJSON(c.results)
		if err != nil {
			fmt.Printf(c.color("Error: %v\n", "red"), err)
			return
		}
		fmt.Println(json)
	} else if arg == "--summary" {
		fmt.Println(c.reporter.ExportSummary(c.results))
	} else {
		id, err := strconv.Atoi(arg)
		if err != nil {
			fmt.Println(c.color("Invalid ID.", "red"))
			return
		}
		if id < 1 || id > len(c.results) {
			fmt.Println(c.color("ID out of range.", "red"))
			return
		}
		c.reporter.PrintFindingDetail(c.results[id-1])
	}
}

func (c *CLI) handleStatus() {
	fmt.Println(c.color("=== Current Configuration ===", "cyan"))

	aiProviders := []string{}
	if c.config.OpenAIKey != "" {
		aiProviders = append(aiProviders, "OpenAI")
	}
	if c.config.AnthropicKey != "" {
		aiProviders = append(aiProviders, "Anthropic")
	}
	if c.config.OllamaURL != "" {
		aiProviders = append(aiProviders, "Ollama")
	}

	fmt.Printf("Configured AI Providers: %s\n", strings.Join(aiProviders, ", "))
	fmt.Printf("Default AI: %s\n", c.config.DefaultAI)
	fmt.Printf("Ollama URL: %s\n", c.config.OllamaURL)
	fmt.Printf("Ollama Model: %s\n", c.config.OllamaModel)

	fmt.Println()
	fmt.Printf("Total findings: %d\n", len(c.results))
}

func (c *CLI) handleExport(args []string) {
	if len(c.results) == 0 {
		fmt.Println(c.color("No results to export. Run 'scan' first.", "red"))
		return
	}

	if len(args) < 2 {
		fmt.Println(c.color("Usage: export <format> <filename>", "red"))
		return
	}

	format := strings.ToLower(args[0])
	filename := args[1]

	var content string
	var err error

	switch format {
	case "json":
		content, err = c.reporter.ExportJSON(c.results)
	case "txt", "text":
		content = c.reporter.ExportSummary(c.results)
		content += "\n\n"
		content += c.reporter.ExportSummary(c.results)
	default:
		fmt.Printf(c.color("Unknown format: %s\n", "red"), format)
		return
	}

	if err != nil {
		fmt.Printf(c.color("Export error: %v\n", "red"), err)
		return
	}

	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		fmt.Printf(c.color("File write error: %v\n", "red"), err)
		return
	}

	fmt.Printf(c.color("Exported to %s\n", "green"), filename)
}

func (c *CLI) handleRules() {
	rules := c.scanner.GetRules()
	fmt.Printf(c.color("\n=== Available Rules: %d ===\n", "cyan"), len(rules))

	serviceCount := c.scanner.GetServiceCount()
	for service, count := range serviceCount {
		fmt.Printf("  %s: %d rules\n", service, count)
	}
}

func (c *CLI) isAIConfigured() bool {
	return c.config.OpenAIKey != "" || c.config.AnthropicKey != "" || c.config.OllamaURL != ""
}

func (c *CLI) printBanner() {
	banner := `
___ ___ ___ ___ ___ _____ _  _ _  _ _  _ _____ ___ ___ 
 / __| __/ __| _ \ __/_   _| || | || | || |_   _| __| _ \
 \__ \ _| (__|   / _|  | | | __ | || | __ | | | | _||   /
 |___/___\___|_|_\___| |_| |_||_|\__/|_||_| |_| |___|_|_\
 
 < AI_POWERED::SECRET_SCANNER_v1.0 />
 < 175+_PATTERNS::MULTI_AI::REALTIME_VALIDATION />`

	fmt.Println(c.color(banner, "cyan"))
	c.running = true
}

func (c *CLI) handleReport(args []string) {
	if len(c.results) == 0 {
		fmt.Println(c.color("No results. Run 'scan' first.", "yellow"))
		return
	}

	target := "Local Scan"
	if len(args) > 0 {
		target = args[0]
	}

	report := analyzer.GenerateReport(c.results, target)
	fmt.Println(c.color(report, "white"))
}

func (c *CLI) color(text, color string) string {
	return text
}

func extractSecretValue(s string) string {
	parts := strings.Split(s, `"`)
	if len(parts) > 1 {
		return parts[1]
	}
	parts = strings.Split(s, `'`)
	if len(parts) > 1 {
		return parts[1]
	}
	parts = strings.Split(s, "=")
	if len(parts) > 1 {
		return strings.TrimSpace(parts[1])
	}
	return s
}

func RunCLI() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	cli := NewCLI()
	cli.Run()
}