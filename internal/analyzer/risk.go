package analyzer

import (
	"fmt"
	"strings"

	"secrethunter/internal/models"
)

type RiskInfo struct {
	Category      string
	Impact        string
	Description   string
	Recommendation string
	CVSSScore     float64
	Regulatory    []string
}

var RiskDatabase = map[string]RiskInfo{
	// Cloud Providers
	"aws-access-key": {
		Category:      "Cloud Infrastructure",
		Impact:        "Full access to AWS resources, data breach, financial loss",
		Description:   "AWS Access Key ID - grants programmatic access to AWS",
		Recommendation: "Rotate immediately. Check CloudTrail for unauthorized access.",
		CVSSScore:     9.1,
		Regulatory:    []string{"PCI-DSS", "SOC2", "GDPR"},
	},
	"aws-secret-key": {
		Category:      "Cloud Infrastructure",
		Impact:        "Complete AWS account compromise, data theft, crypto mining",
		Description:   "AWS Secret Access Key - can perform any AWS action",
		Recommendation: "Rotate immediately. Review IAM roles and permissions.",
		CVSSScore:     9.8,
		Regulatory:    []string{"PCI-DSS", "SOC2", "GDPR"},
	},
	"google-api-key": {
		Category:      "Cloud API",
		Impact:        "Unauthorized API usage, billing fraud, data access",
		Description:   "Google Cloud API Key - access to Google services",
		Recommendation: "Rotate key. Set up API restrictions and quota limits.",
		CVSSScore:     8.5,
		Regulatory:    []string{"GDPR", "HIPAA"},
	},
	"azure-client-secret": {
		Category:      "Cloud Identity",
		Impact:        "Azure AD compromise, data exfiltration, privilege escalation",
		Description:   "Azure Client Secret - application authentication",
		Recommendation: "Rotate secret. Check for suspicious sign-ins.",
		CVSSScore:     9.0,
		Regulatory:    []string{"SOC2", "GDPR", "HIPAA"},
	},
	"qiniu-access-key": {
		Category:      "Cloud Storage",
		Impact:        "Data breach, storage costs, content manipulation",
		Description:   "Qiniu Cloud Storage Access Key",
		Recommendation: "Rotate key. Review bucket policies and access logs.",
		CVSSScore:     7.5,
		Regulatory:    []string{"GDPR"},
	},

	// AI Services
	"openai-api-key": {
		Category:      "AI/ML API",
		Impact:        "Unauthorized API usage, billing fraud, data exfiltration",
		Description:   "OpenAI API Key - access to GPT models and services",
		Recommendation: "Rotate key immediately. Check usage for anomalies.",
		CVSSScore:     8.0,
		Regulatory:    []string{"GDPR"},
	},
	"anthropic-api-key": {
		Category:      "AI/ML API",
		Impact:        "Unauthorized AI usage, billing fraud",
		Description:   "Anthropic Claude API Key",
		Recommendation: "Rotate key. Monitor API usage.",
		CVSSScore:     8.0,
		Regulatory:    []string{"GDPR"},
	},
	"huggingface-token": {
		Category:      "AI/ML Platform",
		Impact:        "Model theft, unauthorized inference, data access",
		Description:   "HuggingFace Access Token",
		Recommendation: "Rotate token. Review model permissions.",
		CVSSScore:     7.5,
		Regulatory:    []string{"GDPR"},
	},

	// DevOps
	"github-token": {
		Category:      "Version Control",
		Impact:        "Code theft, repository compromise, supply chain attack",
		Description:   "GitHub Personal Access Token",
		Recommendation: "Revoke token immediately. Review repo access.",
		CVSSScore:     9.2,
		Regulatory:    []string{"SOC2", "PCI-DSS"},
	},
	"github-oauth": {
		Category:      "Version Control",
		Impact:        "Account takeover, data theft",
		Description:   "GitHub OAuth Token",
		Recommendation: "Revoke token. Check authorized apps.",
		CVSSScore:     9.0,
		Regulatory:    []string{"SOC2"},
	},
	"gitlab-pat": {
		Category:      "Version Control",
		Impact:        "Code theft, repository compromise",
		Description:   "GitLab Personal Access Token",
		Recommendation: "Revoke token. Review access logs.",
		CVSSScore:     9.0,
		Regulatory:    []string{"SOC2"},
	},
	"heroku-api-key": {
		Category:      "PaaS",
		Impact:        "Application compromise, data breach",
		Description:   "Heroku API Key",
		Recommendation: "Rotate key. Check for unauthorized deployments.",
		CVSSScore:     8.0,
		Regulatory:    []string{"SOC2"},
	},

	// Communication
	"slack-bot-token": {
		Category:      "Communication",
		Impact:        "Channel access, message exfiltration, phishing",
		Description:   "Slack Bot Token",
		Recommendation: "Rotate token. Review app permissions.",
		CVSSScore:     7.5,
		Regulatory:    []string{"GDPR"},
	},
	"telegram-bot-token": {
		Category:      "Communication",
		Impact:        "Bot compromise, message access, group control",
		Description:   "Telegram Bot Token",
		Recommendation: "Rotate token via @BotFather.",
		CVSSScore:     7.0,
		Regulatory:    []string{"GDPR"},
	},
	"twilio-account-sid": {
		Category:      "Communication",
		Impact:        "SMS fraud, call manipulation",
		Description:   "Twilio Account SID and Auth Token",
		Recommendation: "Rotate credentials. Check call logs.",
		CVSSScore:     7.5,
		Regulatory:    []string{"SOC2"},
	},

	// Payments
	"stripe-secret-key": {
		Category:      "Payment",
		Impact:        "Financial fraud, chargebacks, data theft",
		Description:   "Stripe Secret Key - live payment processing",
		Recommendation: "ROTATE IMMEDIATELY! Review transactions for fraud.",
		CVSSScore:     9.8,
		Regulatory:    []string{"PCI-DSS", "SOC2"},
	},
	"stripe-publishable-key": {
		Category:      "Payment",
		Impact:        "Limited - can only create tokens",
		Description:   "Stripe Publishable Key - client-side use only",
		Recommendation: "Less critical but rotate if exposed.",
		CVSSScore:     4.0,
		Regulatory:    []string{"PCI-DSS"},
	},

	// Database
	"mongodb-conn": {
		Category:      "Database",
		Impact:        "Data breach, data deletion, ransomware",
		Description:   "MongoDB Connection String with credentials",
		Recommendation: "Rotate passwords. Review IP access lists.",
		CVSSScore:     9.5,
		Regulatory:    []string{"GDPR", "HIPAA", "PCI-DSS"},
	},
	"postgres-conn": {
		Category:      "Database",
		Impact:        "Data breach, data theft",
		Description:   "PostgreSQL Connection String",
		Recommendation: "Rotate passwords. Enable SSL.",
		CVSSScore:     9.5,
		Regulatory:    []string{"GDPR", "HIPAA"},
	},
	"mysql-conn": {
		Category:      "Database",
		Impact:        "Data breach, data theft",
		Description:   "MySQL Connection String",
		Recommendation: "Rotate passwords. Review user privileges.",
		CVSSScore:     9.5,
		Regulatory:    []string{"GDPR", "HIPAA"},
	},
	"redis-conn": {
		Category:      "Database",
		Impact:        "Data exposure, cache poisoning, session hijacking",
		Description:   "Redis Connection String",
		Recommendation: "Enable authentication. Review access.",
		CVSSScore:     8.5,
		Regulatory:    []string{"GDPR"},
	},

	// Cryptographic
	"rsa-private-key": {
		Category:      "Cryptographic",
		Impact:        "Identity compromise, data decryption, man-in-middle",
		Description:   "RSA Private Key - cryptographic identity",
		Recommendation: "Generate new key pair immediately. Revoke old cert.",
		CVSSScore:     10.0,
		Regulatory:    []string{"PCI-DSS", "SOC2", "GDPR"},
	},
	"ec-private-key": {
		Category:      "Cryptographic",
		Impact:        "Identity compromise, signature forgery",
		Description:   "EC Private Key",
		Recommendation: "Generate new key pair. Revoke old certificate.",
		CVSSScore:     10.0,
		Regulatory:    []string{"PCI-DSS", "SOC2"},
	},
	"jwt-secret": {
		Category:      "Authentication",
		Impact:        "Token forgery, authentication bypass",
		Description:   "JWT Secret Key",
		Recommendation: "Rotate secret. Invalidate existing tokens.",
		CVSSScore:     9.0,
		Regulatory:    []string{"GDPR", "SOC2"},
	},

	// Generic
	"generic-api-key": {
		Category:      "Generic",
		Impact:        "Service-specific - requires manual analysis",
		Description:   "Generic API Key pattern",
		Recommendation: "Analyze context to determine service and risk.",
		CVSSScore:     5.0,
		Regulatory:    []string{},
	},
	"generic-password": {
		Category:      "Credentials",
		Impact:        "Account compromise, data breach",
		Description:   "Generic password in code",
		Recommendation: "Use environment variables or secrets manager.",
		CVSSScore:     6.0,
		Regulatory:    []string{"GDPR"},
	},
	"env-secret": {
		Category:      "Configuration",
		Impact:        "Depends on secret type",
		Description:   "Environment variable containing secret",
		Recommendation: "Move to secrets management solution.",
		CVSSScore:     5.5,
		Regulatory:    []string{"SOC2"},
	},
	"json-secret": {
		Category:      "Configuration",
		Impact:        "Service-specific credential exposure",
		Description:   "JSON file containing secrets",
		Recommendation: "Add to .gitignore. Use env vars.",
		CVSSScore:     6.0,
		Regulatory:    []string{"GDPR"},
	},
	"password-in-url": {
		Category:      "Credentials",
		Impact:        "Account compromise via URL logs",
		Description:   "Password embedded in URL",
		Recommendation: "Use authentication headers instead.",
		CVSSScore:     7.0,
		Regulatory:    []string{"GDPR"},
	},
	"bearer-token": {
		Category:      "Authentication",
		Impact:        "Token theft, session hijacking",
		Description:   "Bearer token in headers",
		Recommendation: "Rotate token. Review access logs.",
		CVSSScore:     7.5,
		Regulatory:    []string{"GDPR", "SOC2"},
	},
	"basic-auth": {
		Category:      "Authentication",
		Impact:        "Credential theft",
		Description:   "Basic authentication header",
		Recommendation: "Use OAuth or API keys instead.",
		CVSSScore:     7.0,
		Regulatory:    []string{"GDPR"},
	},
}

func GetRiskInfo(ruleID string) *RiskInfo {
	if risk, ok := RiskDatabase[ruleID]; ok {
		return &risk
	}

	// Check for partial matches
	for key, risk := range RiskDatabase {
		if strings.Contains(ruleID, key) || strings.Contains(key, ruleID) {
			return &risk
		}
	}

	return &RiskInfo{
		Category:      "Unknown",
		Impact:        "Requires manual analysis",
		Description:   fmt.Sprintf("Rule: %s", ruleID),
		Recommendation: "Review manually to determine risk level.",
		CVSSScore:     5.0,
		Regulatory:    []string{},
	}
}

func CalculateOverallRisk(findings []models.Finding) (float64, string, []string) {
	var totalScore float64
	var criticalCount int
	var categories []string
	categorySet := make(map[string]bool)

	for _, f := range findings {
		risk := GetRiskInfo(f.RuleID)
		totalScore += risk.CVSSScore

		if risk.CVSSScore >= 9.0 {
			criticalCount++
		}

		if !categorySet[risk.Category] {
			categorySet[risk.Category] = true
			categories = append(categories, risk.Category)
		}
	}

	avgScore := totalScore / float64(len(findings))

	riskLevel := "LOW"
	if avgScore >= 9.0 {
		riskLevel = "CRITICAL"
	} else if avgScore >= 7.5 {
		riskLevel = "HIGH"
	} else if avgScore >= 5.0 {
		riskLevel = "MEDIUM"
	}

	if criticalCount > 0 {
		riskLevel = "CRITICAL"
	}

	return avgScore, riskLevel, categories
}

func GenerateReport(findings []models.Finding, target string) string {
	avgScore, riskLevel, categories := CalculateOverallRisk(findings)

	report := fmt.Sprintf(`
═══════════════════════════════════════════════════════════════════
                    SECRET HUNTER - RISK REPORT
═══════════════════════════════════════════════════════════════════

TARGET: %s
TOTAL FINDINGS: %d
OVERALL RISK: %s (CVSS: %.1f)

═══════════════════════════════════════════════════════════════════
                        RISK BREAKDOWN
═══════════════════════════════════════════════════════════════════

RISK LEVEL: %s

`, target, len(findings), riskLevel, avgScore, riskLevel)

	if len(categories) > 0 {
		report += "AFFECTED CATEGORIES:\n"
		for _, cat := range categories {
			report += fmt.Sprintf("  ⚠ %s\n", cat)
		}
		report += "\n"
	}

	report += "═══════════════════════════════════════════════════════════════════\n"
	report += "                      FINDINGS DETAIL\n"
	report += "═══════════════════════════════════════════════════════════════════\n\n"

	for i, f := range findings {
		risk := GetRiskInfo(f.RuleID)
		report += fmt.Sprintf("[%d] %s\n", i+1, f.RuleName)
		report += fmt.Sprintf("    Severity: %s | CVSS: %.1f\n", f.Severity, risk.CVSSScore)
		report += fmt.Sprintf("    File: %s:%d\n", f.File, f.Line)
		report += fmt.Sprintf("    Impact: %s\n", risk.Impact)
		report += fmt.Sprintf("    Recommendation: %s\n", risk.Recommendation)

		if len(risk.Regulatory) > 0 {
			report += fmt.Sprintf("    Compliance: %s\n", strings.Join(risk.Regulatory, ", "))
		}
		report += "\n"
	}

	report += `
═══════════════════════════════════════════════════════════════════
                        REMEDIATION STEPS
═══════════════════════════════════════════════════════════════════

1. IMMEDIATE ACTIONS:
   - Rotate all exposed credentials immediately
   - Review access logs for unauthorized usage
   - Enable alerts for suspicious activity

2. PREVENTION:
   - Use secrets management tools (Vault, AWS Secrets Manager)
   - Implement pre-commit hooks to detect secrets
   - Add sensitive files to .gitignore

3. COMPLIANCE:
   - Document incident for compliance reporting
   - Review and update security policies
   - Conduct security awareness training

═══════════════════════════════════════════════════════════════════
`

	return report
}