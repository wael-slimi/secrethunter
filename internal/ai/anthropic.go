package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"secrethunter/internal/models"
)

type AnthropicProvider struct{}

func NewAnthropicProvider() *AnthropicProvider {
	return &AnthropicProvider{}
}

func (p *AnthropicProvider) Name() string {
	return "anthropic"
}

func (p *AnthropicProvider) IsConfigured(config *models.Config) bool {
	return config.AnthropicKey != ""
}

type AnthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type AnthropicRequest struct {
	Model      string          `json:"model"`
	MaxTokens  int             `json:"max_tokens"`
	Messages   []AnthropicMessage `json:"messages"`
	System     string          `json:"system"`
	Temperature float64        `json:"temperature,omitempty"`
}

type AnthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type AnthropicResponse struct {
	Content []AnthropicContent `json:"content"`
}

func (p *AnthropicProvider) Analyze(finding models.Finding, config *models.Config) (*models.AIAnalysis, error) {
	if config.AnthropicKey == "" {
		return nil, fmt.Errorf("Anthropic API key not configured")
	}

	systemPrompt := GetSystemPrompt()
	userPrompt := GetUserPrompt(finding)

	jsonData, err := json.Marshal(AnthropicRequest{
		Model:      "claude-3-5-sonnet-20241022",
		MaxTokens:  2000,
		System:     systemPrompt,
		Messages: []AnthropicMessage{
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.1,
	})

	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", config.AnthropicKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Anthropic API error: %s", string(body))
	}

	var anthropicResp AnthropicResponse
	if err := json.Unmarshal(body, &anthropicResp); err != nil {
		return nil, err
	}

	if len(anthropicResp.Content) == 0 {
		return nil, fmt.Errorf("no response from Anthropic")
	}

	content := anthropicResp.Content[0].Text
	content = extractJSON(content)

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return p.parseTextResponse(content)
	}

	return p.mapToAnalysis(result)
}

func (p *AnthropicProvider) mapToAnalysis(result map[string]interface{}) (*models.AIAnalysis, error) {
	isReal := false
	if v, ok := result["is_real_secret"].(bool); ok {
		isReal = v
	}

	confidence := 50
	if v, ok := result["confidence"].(float64); ok {
		confidence = int(v)
	}

	provider := ""
	if v, ok := result["provider"].(string); ok {
		provider = v
	}

	secretType := ""
	if v, ok := result["secret_type"].(string); ok {
		secretType = v
	}

	riskLevel := "medium"
	if v, ok := result["risk_level"].(string); ok {
		riskLevel = v
	}

	reasoning := ""
	if v, ok := result["reasoning"].(string); ok {
		reasoning = v
	}

	recommendation := ""
	if v, ok := result["recommendation"].(string); ok {
		recommendation = v
	}

	contextInfo := models.ContextInfo{}
	if ctx, ok := result["context_analysis"].(map[string]interface{}); ok {
		if v, ok := ctx["file_type"].(string); ok {
			contextInfo.FileType = v
		}
		if v, ok := ctx["variable_name"].(string); ok {
			contextInfo.VariableName = v
		}
		if v, ok := ctx["surrounding_code"].(string); ok {
			contextInfo.SurroundingCode = v
		}
		if v, ok := ctx["environment"].(string); ok {
			contextInfo.Environment = v
		}
	}

	return &models.AIAnalysis{
		IsRealSecret:    isReal,
		Confidence:      confidence,
		Provider:        provider,
		SecretType:      secretType,
		RiskLevel:       riskLevel,
		Reasoning:       reasoning,
		Recommendation:  recommendation,
		ContextAnalysis: contextInfo,
	}, nil
}

func (p *AnthropicProvider) parseTextResponse(content string) (*models.AIAnalysis, error) {
	result := &models.AIAnalysis{
		IsRealSecret:   true,
		Confidence:     50,
		RiskLevel:      "medium",
		Reasoning:      content,
		Recommendation: "Manual review required",
	}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(line, "false positive") {
			result.IsRealSecret = false
			result.Confidence = 80
		}
		if strings.Contains(line, "confidence:") {
			fmt.Sscanf(line, "%*s confidence: %d", &result.Confidence)
		}
		if strings.Contains(line, "provider:") {
			result.Provider = strings.TrimSpace(strings.Split(line, ":")[1])
		}
	}

	return result, nil
}