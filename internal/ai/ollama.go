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

type OllamaProvider struct{}

func NewOllamaProvider() *OllamaProvider {
	return &OllamaProvider{}
}

func (p *OllamaProvider) Name() string {
	return "ollama"
}

func (p *OllamaProvider) IsConfigured(config *models.Config) bool {
	if config.OllamaURL == "" {
		return false
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", config.OllamaURL+"/api/tags", nil)
	resp, err := client.Do(req)
	return err == nil && resp.StatusCode == 200
}

type OllamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OllamaRequest struct {
	Model    string        `json:"model"`
	Messages []OllamaMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

type OllamaResponse struct {
	Message OllamaMessage `json:"message"`
	Done    bool          `json:"done"`
}

func (p *OllamaProvider) Analyze(finding models.Finding, config *models.Config) (*models.AIAnalysis, error) {
	if config.OllamaURL == "" {
		return nil, fmt.Errorf("Ollama not configured")
	}

	model := config.OllamaModel
	if model == "" {
		model = "llama3"
	}

	systemPrompt := GetSystemPrompt()
	userPrompt := GetUserPrompt(finding)

	jsonData, err := json.Marshal(OllamaRequest{
		Model: model,
		Messages: []OllamaMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Stream: false,
	})

	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", config.OllamaURL+"/api/chat", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Ollama connection failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Ollama error: %s", string(body))
	}

	var ollamaResp OllamaResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return nil, err
	}

	content := ollamaResp.Message.Content
	content = extractJSON(content)

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return p.parseTextResponse(content)
	}

	return p.mapToAnalysis(result)
}

func (p *OllamaProvider) mapToAnalysis(result map[string]interface{}) (*models.AIAnalysis, error) {
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

func (p *OllamaProvider) parseTextResponse(content string) (*models.AIAnalysis, error) {
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

func extractJSON(text string) string {
	start := strings.Index(text, "{")
	if start == -1 {
		start = strings.Index(text, "[")
		if start == -1 {
			return text
		}
	}

	end := strings.LastIndex(text, "}")
	if end == -1 {
		end = strings.LastIndex(text, "]")
		if end == -1 {
			return text
		}
	}

	if end >= start {
		return text[start : end+1]
	}
	return text
}