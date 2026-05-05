package models

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo    Severity = "info"
)

type Finding struct {
	ID           string    `json:"id"`
	RuleID       string    `json:"rule_id"`
	RuleName     string    `json:"rule_name"`
	Severity     Severity  `json:"severity"`
	Match        string    `json:"match"`
	File         string    `json:"file"`
	Line         int       `json:"line"`
	Commit       string    `json:"commit"`
	Entropy      float64   `json:"entropy"`
	Tags         []string  `json:"tags"`
	Context      string    `json:"context"`
	Timestamp    time.Time `json:"timestamp"`
	AIAnalysis   *AIAnalysis `json:"ai_analysis,omitempty"`
	Validation   *ValidationResult `json:"validation,omitempty"`
}

type AIAnalysis struct {
	IsRealSecret    bool      `json:"is_real_secret"`
	Confidence      int       `json:"confidence"`
	Provider        string    `json:"provider"`
	SecretType      string    `json:"secret_type"`
	RiskLevel       string    `json:"risk_level"`
	Reasoning       string    `json:"reasoning"`
	Recommendation  string    `json:"recommendation"`
	ContextAnalysis ContextInfo `json:"context_analysis"`
}

type ContextInfo struct {
	FileType      string `json:"file_type"`
	VariableName string `json:"variable_name"`
	SurroundingCode string `json:"surrounding_code"`
	Environment  string `json:"environment"`
}

type ValidationResult struct {
	IsValid     bool   `json:"is_valid"`
	Service     string `json:"service"`
	CheckedAt   string `json:"checked_at"`
	Error       string `json:"error,omitempty"`
}

type ScanTarget struct {
	Type  string
	Path  string
	URL   string
}

type ScanResult struct {
	Target     ScanTarget  `json:"target"`
	Findings   []Finding   `json:"findings"`
	StartTime  time.Time   `json:"start_time"`
	EndTime    time.Time   `json:"end_time"`
	Duration   float64     `json:"duration"`
	TotalFound int         `json:"total_found"`
	Filtered   int         `json:"filtered"`
}