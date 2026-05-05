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

type OpenAIProvider struct{}

func NewOpenAIProvider() *OpenAIProvider {
	return &OpenAIProvider{}
}

func (p *OpenAIProvider) Name() string {
	return "openai"
}

func (p *OpenAIProvider) IsConfigured(config *models.Config) bool {
	return config.OpenAIKey != ""
}

type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIRequest struct {
	Model       string        `json:"model"`
	Messages    []OpenAIMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type OpenAIChoice struct {
	Message OpenAIMessage `json:"message"`
}

type OpenAIResponse struct {
	Choices []OpenAIChoice `json:"choices"`
}

func (p *OpenAIProvider) Analyze(finding models.Finding, config *models.Config) (*models.AIAnalysis, error) {
	if config.OpenAIKey == "" {
		return nil, fmt.Errorf("OpenAI API key not configured")
	}

	systemPrompt := GetSystemPrompt()
	userPrompt := GetUserPrompt(finding)

	messages := []OpenAIMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}

	jsonData, err := json.Marshal(OpenAIRequest{
		Model:       "gpt-4o",
		Messages:    messages,
		Temperature: 0.1,
	})

	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.OpenAIKey)

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
		return nil, fmt.Errorf("OpenAI API error: %s", string(body))
	}

	var openaiResp OpenAIResponse
	if err := json.Unmarshal(body, &openaiResp); err != nil {
		return nil, err
	}

	if len(openaiResp.Choices) == 0 {
		return nil, fmt.Errorf("no response from OpenAI")
	}

	content := openaiResp.Choices[0].Message.Content

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		content = extractJSON(content)
		if err := json.Unmarshal([]byte(content), &result); err != nil {
			return p.parseTextResponse(content)
		}
	}

	return p.mapToAnalysis(result)
}

func (p *OpenAIProvider) mapToAnalysis(result map[string]interface{}) (*models.AIAnalysis, error) {
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

func (p *OpenAIProvider) parseTextResponse(content string) (*models.AIAnalysis, error) {
	lines := strings.Split(content, "\n")

	result := &models.AIAnalysis{
		IsRealSecret:   true,
		Confidence:     50,
		RiskLevel:      "medium",
		Reasoning:      content,
		Recommendation: "Manual review required",
	}

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

// extractJSON is defined in ollama.go to avoid duplication

func init() {
	engine := NewAIEngine()
	engine.RegisterProvider("openai", NewOpenAIProvider())
}

var DefaultEngine = func() *AIEngine {
	engine := NewAIEngine()
	engine.RegisterProvider("openai", NewOpenAIProvider())
	engine.RegisterProvider("anthropic", NewAnthropicProvider())
	engine.RegisterProvider("ollama", NewOllamaProvider())
	return engine
}()