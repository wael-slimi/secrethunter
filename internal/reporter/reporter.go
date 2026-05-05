package reporter

import (
	"encoding/json"
	"fmt"
	"strings"

	"secrethunter/internal/models"
)

type Reporter struct {
	colorEnabled bool
}

func NewReporter() *Reporter {
	return &Reporter{
		colorEnabled: true,
	}
}

func (r *Reporter) SetColor(enabled bool) {
	r.colorEnabled = enabled
}

func (r *Reporter) PrintFindings(findings []models.Finding) {
	if len(findings) == 0 {
		fmt.Println("No findings.")
		return
	}

	r.printHeader(fmt.Sprintf("Found %d potential secrets", len(findings)))
	fmt.Println()

	for i, f := range findings {
		r.printFinding(i+1, f)
		fmt.Println()
	}
}

func (r *Reporter) printFinding(num int, f models.Finding) {
	severityColor := r.getSeverityColor(f.Severity)
	severityStr := r.color(fmt.Sprintf("[%s]", strings.ToUpper(string(f.Severity))), severityColor)

	fmt.Printf("  %d. %s %s\n", num, severityStr, f.RuleName)
	fmt.Printf("      File: %s:%d\n", f.File, f.Line)
	fmt.Printf("      Match: %s\n", r.maskSecret(f.Match))

	if len(f.Tags) > 0 {
		fmt.Printf("      Tags: %s\n", strings.Join(f.Tags, ", "))
	}

	if f.AIAnalysis != nil {
		r.printAIAnalysis(f.AIAnalysis)
	}

	if f.Validation != nil {
		r.printValidation(f.Validation)
	}
}

func (r *Reporter) printAIAnalysis(analysis *models.AIAnalysis) {
	statusStr := "REAL"
	statusColor := "red"
	if !analysis.IsRealSecret {
		statusStr = "FALSE POSITIVE"
		statusColor = "green"
	}

	confidenceColor := "yellow"
	if analysis.Confidence >= 80 {
		confidenceColor = "green"
	} else if analysis.Confidence <= 30 {
		confidenceColor = "red"
	}

	fmt.Printf("      %s: %s\n", r.color("AI Analysis:", "cyan"),
		r.color(statusStr, statusColor))
	fmt.Printf("      %s: %d%% (%s)\n", r.color("Confidence:", "cyan"),
		analysis.Confidence, r.color(analysis.RiskLevel, confidenceColor))
	fmt.Printf("      %s: %s\n", r.color("Provider:", "cyan"), analysis.Provider)
	if analysis.Reasoning != "" {
		reasoning := analysis.Reasoning
		if len(reasoning) > 100 {
			reasoning = reasoning[:100] + "..."
		}
		fmt.Printf("      %s: %s\n", r.color("Reason:", "cyan"), reasoning)
	}
}

func (r *Reporter) printValidation(validation *models.ValidationResult) {
	statusStr := "VALID"
	statusColor := "green"
	if !validation.IsValid {
		statusStr = "INVALID"
		statusColor = "red"
	}

	fmt.Printf("      %s: %s (%s)\n", r.color("Validation:", "cyan"),
		r.color(statusStr, statusColor), validation.Service)
	if validation.Error != "" {
		fmt.Printf("      %s: %s\n", r.color("Error:", "cyan"), validation.Error)
	}
}

func (r *Reporter) printHeader(title string) {
	border := strings.Repeat("=", len(title)+4)
	fmt.Println(r.color(border, "cyan"))
	fmt.Printf("  %s\n", r.color(title, "cyan"))
	fmt.Println(r.color(border, "cyan"))
}

func (r *Reporter) getSeverityColor(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical:
		return "red"
	case models.SeverityHigh:
		return "magenta"
	case models.SeverityMedium:
		return "yellow"
	case models.SeverityLow:
		return "blue"
	default:
		return "white"
	}
}

func (r *Reporter) color(text string, _ string) string {
	if !r.colorEnabled {
		return text
	}
	return text
}

func (r *Reporter) maskSecret(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

func (r *Reporter) ExportJSON(findings []models.Finding) (string, error) {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (r *Reporter) ExportSummary(findings []models.Finding) string {
	var lines []string

	bySeverity := make(map[models.Severity]int)
	byService := make(map[string]int)

	for _, f := range findings {
		bySeverity[f.Severity]++
		service := detectServiceFromTags(f.Tags)
		if service == "" {
			service = f.RuleName
		}
		byService[service]++
	}

	lines = append(lines, r.color("=== Scan Summary ===", "cyan"))
	lines = append(lines, fmt.Sprintf("Total Findings: %d", len(findings)))
	lines = append(lines, "")

	lines = append(lines, r.color("By Severity:", "yellow"))
	for _, sev := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow} {
		if count := bySeverity[sev]; count > 0 {
			lines = append(lines, fmt.Sprintf("  %s: %d", strings.ToUpper(string(sev)), count))
		}
	}
	lines = append(lines, "")

	lines = append(lines, r.color("By Service:", "yellow"))
	for service, count := range byService {
		lines = append(lines, fmt.Sprintf("  %s: %d", service, count))
	}

	return strings.Join(lines, "\n")
}

func detectServiceFromTags(tags []string) string {
	services := []string{"AWS", "Google", "Azure", "GitHub", "OpenAI", "Stripe", "Slack", "Twilio", "DigitalOcean", "Cloudflare", "Heroku", "Qiniu", "Anthropic"}
	for _, tag := range tags {
		for _, service := range services {
			if strings.EqualFold(tag, service) {
				return service
			}
		}
	}
	return ""
}

func (r *Reporter) PrintTable(findings []models.Finding) {
	if len(findings) == 0 {
		fmt.Println("No findings.")
		return
	}

	fmt.Printf("%-4s %-10s %-40s %-30s\n", "Num", "Severity", "Rule", "File")
	fmt.Println(strings.Repeat("-", 90))

	for i, f := range findings {
		sev := strings.ToUpper(string(f.Severity))
		rule := f.RuleName
		if len(rule) > 40 {
			rule = rule[:37] + "..."
		}
		file := f.File
		if len(file) > 30 {
			file = file[:27] + "..."
		}
		fmt.Printf("%-4d %-10s %-40s %-30s\n", i+1, sev, rule, file)
	}
}

func (r *Reporter) PrintFindingDetail(finding models.Finding) {
	fmt.Println()
	fmt.Println(r.color("═══════════════════════════════════════════════════════════════", "cyan"))
	fmt.Printf("  Finding: %s\n", finding.RuleName)
	fmt.Println(r.color("═══════════════════════════════════════════════════════════════", "cyan"))

	fmt.Printf("\n%s: %s\n", r.color("Severity", "yellow"), finding.Severity)
	fmt.Printf("%s: %s\n", r.color("File", "yellow"), finding.File)
	fmt.Printf("%s: %d\n", r.color("Line", "yellow"), finding.Line)
	fmt.Printf("%s: %s\n", r.color("Match", "yellow"), finding.Match)
	fmt.Printf("%s: %.2f\n", r.color("Entropy", "yellow"), finding.Entropy)

	if len(finding.Tags) > 0 {
		fmt.Printf("%s: %s\n", r.color("Tags", "yellow"), strings.Join(finding.Tags, ", "))
	}

	fmt.Printf("\n%s:\n%s\n", r.color("Context", "yellow"), finding.Context)

	if finding.AIAnalysis != nil {
		fmt.Printf("\n%s:\n", r.color("AI Analysis", "yellow"))
		fmt.Printf("  %s: %v\n", r.color("Is Real", "cyan"), finding.AIAnalysis.IsRealSecret)
		fmt.Printf("  %s: %d%%\n", r.color("Confidence", "cyan"), finding.AIAnalysis.Confidence)
		fmt.Printf("  %s: %s\n", r.color("Provider", "cyan"), finding.AIAnalysis.Provider)
		fmt.Printf("  %s: %s\n", r.color("Risk Level", "cyan"), finding.AIAnalysis.RiskLevel)
		fmt.Printf("  %s: %s\n", r.color("Reasoning", "cyan"), finding.AIAnalysis.Reasoning)
	}

	if finding.Validation != nil {
		fmt.Printf("\n%s:\n", r.color("Validation", "yellow"))
		fmt.Printf("  %s: %v\n", r.color("Valid", "cyan"), finding.Validation.IsValid)
		fmt.Printf("  %s: %s\n", r.color("Service", "cyan"), finding.Validation.Service)
		if finding.Validation.Error != "" {
			fmt.Printf("  %s: %s\n", r.color("Error", "cyan"), finding.Validation.Error)
		}
	}
}