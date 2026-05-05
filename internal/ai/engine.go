package ai

import (
	"fmt"
	"strings"

	"secrethunter/internal/models"
)

type Provider interface {
	Name() string
	Analyze(finding models.Finding, config *models.Config) (*models.AIAnalysis, error)
	IsConfigured(config *models.Config) bool
}

type AIEngine struct {
	providers map[string]Provider
	config    *models.Config
}

func NewAIEngine() *AIEngine {
	return &AIEngine{
		providers: make(map[string]Provider),
		config:    models.DefaultConfig(),
	}
}

func (e *AIEngine) RegisterProvider(name string, provider Provider) {
	e.providers[name] = provider
}

func (e *AIEngine) GetProvider(name string) Provider {
	return e.providers[name]
}

func (e *AIEngine) SetConfig(config *models.Config) {
	e.config = config
}

func (e *AIEngine) AvailableProviders() []string {
	var names []string
	for name := range e.providers {
		names = append(names, name)
	}
	return names
}

func (e *AIEngine) AnalyzeWithBestProvider(finding models.Finding) (*models.AIAnalysis, error) {
	providerName := e.config.DefaultAI

	if provider, ok := e.providers[providerName]; ok {
		if provider.IsConfigured(e.config) {
			return provider.Analyze(finding, e.config)
		}
	}

	for _, provider := range e.providers {
		if provider.IsConfigured(e.config) {
			return provider.Analyze(finding, e.config)
		}
	}

	return nil, fmt.Errorf("no AI provider configured")
}

func (e *AIEngine) ConfigureProvider(provider string, key string, extra ...string) error {
	switch provider {
	case "openai":
		e.config.OpenAIKey = key
		if len(extra) > 0 {
			e.config.DefaultAI = "openai"
		}
	case "anthropic":
		e.config.AnthropicKey = key
		if len(extra) > 0 {
			e.config.DefaultAI = "anthropic"
		}
	case "ollama":
		e.config.OllamaURL = "http://localhost:11434"
		if len(extra) > 0 {
			e.config.OllamaModel = extra[0]
		}
		if len(extra) > 1 {
			e.config.OllamaURL = extra[1]
		}
		if len(extra) > 2 {
			e.config.DefaultAI = "ollama"
		}
	}
	return nil
}

func (e *AIEngine) GetConfig() *models.Config {
	return e.config
}

func GetSystemPrompt() string {
	return `You are a Security Expert AI specializing in secret detection and leak analysis.

## Your Task
Analyze potential secret findings and determine:
1. Is it a REAL secret or FALSE POSITIVE?
2. What SERVICE/PROVIDER does it belong to?
3. What is the RISK LEVEL (0-100)?
4. What CONTEXT makes it likely real or fake?

## Analysis Guidelines

### FALSE POSITIVE Indicators:
1. Variable name contains: test, mock, fake, sample, demo, placeholder, example, dummy, temp, dev
2. Value is truncated or incomplete (ends with ...)
3. Commented code or documentation
4. Test files (test_, spec_, *_test.go, test.ts, __tests__, etc.)
5. Variable named "EXAMPLE", "SAMPLE", "DUMMY", "YOUR_KEY_HERE"
6. Known public values or test credentials
7. Environment is clearly development/staging (not production)
8. Value is obviously invalid format for that service type
9. Variable name indicates it's not for production use (local_, test_, sandbox_)

### TRUE POSITIVE Indicators:
1. Variable name matches production: prod_, production_, live_, real_, api_, client_
2. Found in actual application code (not tests)
3. Full value present (not truncated)
4. Appears in multiple files or locations
5. Used in actual API calls or authentication
6. Historical commit shows recent active use
7. Environment is production or not explicitly development
8. Variable names like: api_key, secret_token, access_token, private_key, auth_token

### Context to Analyze:
- File type (source code, config, env file, test file, documentation)
- Variable/function name
- Surrounding code (imports, function calls, initialization)
- Comments or documentation nearby
- Whether it's in a secrets management system (Vault, AWS Secrets Manager, etc.)

## Output Format (JSON)
{
  "is_real_secret": true/false,
  "confidence": 0-100,
  "provider": "AWS/OpenAI/GitHub/etc",
  "secret_type": "Access Key/OAuth Token/API Key/etc",
  "risk_level": "critical/high/medium/low",
  "reasoning": "explanation of why this is/isn't a real secret",
  "recommendation": "action to take (revoke, rotate, ignore, investigate)",
  "context_analysis": {
    "file_type": "config/source/test/doc/env",
    "variable_name": "actual variable name from code",
    "surrounding_code": "relevant code context",
    "environment": "production/staging/development/unknown"
  }
}

Be strict but fair. When in doubt, lean toward marking as potential secret but with lower confidence.`
}

func GetUserPrompt(finding models.Finding) string {
	context := strings.ReplaceAll(finding.Context, "`", "'")
	tags := strings.Join(finding.Tags, ", ")
	return "## Secret Finding to Analyze\n\n### Basic Information\n" +
		fmt.Sprintf("- **Rule ID**: %s\n", finding.RuleID) +
		fmt.Sprintf("- **Rule Name**: %s\n", finding.RuleName) +
		fmt.Sprintf("- **Severity**: %s\n", finding.Severity) +
		fmt.Sprintf("- **File**: %s\n", finding.File) +
		fmt.Sprintf("- **Line**: %d\n", finding.Line) +
		fmt.Sprintf("- **Match**: %s\n\n", finding.Match) +
		"### Context\n" +
		context + "\n\n" +
		fmt.Sprintf("### Tags\n%s\n\n", tags) +
		fmt.Sprintf("### Entropy Score\n%.2f (Higher = more random/likely real secret)\n\n", finding.Entropy) +
		"### Your Analysis\nAnalyze this finding and provide the JSON output as specified in the system prompt."
}