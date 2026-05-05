package validator

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

type Validator struct {
	httpClient *http.Client
}

func NewValidator() *Validator {
	return &Validator{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

type ValidationResult struct {
	IsValid bool
	Error   string
}

func (v *Validator) Validate(finding models.Finding, secretValue string) *models.ValidationResult {
	service := detectService(finding)

	result := &models.ValidationResult{
		Service:   service,
		CheckedAt: time.Now().Format(time.RFC3339),
	}

	switch service {
	case "AWS":
		isValid, err := v.validateAWS(finding.Match, secretValue)
		result.IsValid = isValid
		if err != nil {
			result.Error = err.Error()
		}
	case "OpenAI":
		isValid, err := v.validateOpenAI(secretValue)
		result.IsValid = isValid
		if err != nil {
			result.Error = err.Error()
		}
	case "Anthropic":
		isValid, err := v.validateAnthropic(secretValue)
		result.IsValid = isValid
		if err != nil {
			result.Error = err.Error()
		}
	case "GitHub":
		isValid, err := v.validateGitHub(secretValue)
		result.IsValid = isValid
		if err != nil {
			result.Error = err.Error()
		}
	case "Stripe":
		isValid, err := v.validateStripe(secretValue)
		result.IsValid = isValid
		if err != nil {
			result.Error = err.Error()
		}
	case "Qiniu":
		isValid, err := v.validateQiniu(finding.Match, secretValue)
		result.IsValid = isValid
		if err != nil {
			result.Error = err.Error()
		}
	case "Twilio":
		isValid, err := v.validateTwilio(finding.Match, secretValue)
		result.IsValid = isValid
		if err != nil {
			result.Error = err.Error()
		}
	case "Slack":
		isValid, err := v.validateSlack(secretValue)
		result.IsValid = isValid
		if err != nil {
			result.Error = err.Error()
		}
	case "Cloudflare":
		isValid, err := v.validateCloudflare(secretValue)
		result.IsValid = isValid
		if err != nil {
			result.Error = err.Error()
		}
	case "DigitalOcean":
		isValid, err := v.validateDigitalOcean(secretValue)
		result.IsValid = isValid
		if err != nil {
			result.Error = err.Error()
		}
	case "SendGrid":
		isValid, err := v.validateSendGrid(secretValue)
		result.IsValid = isValid
		if err != nil {
			result.Error = err.Error()
		}
	case "Heroku":
		isValid, err := v.validateHeroku(secretValue)
		result.IsValid = isValid
		if err != nil {
			result.Error = err.Error()
		}
	default:
		result.Error = "Validation not supported for this service"
	}

	return result
}

func detectService(finding models.Finding) string {
	match := finding.Match

	if strings.Contains(match, "AKIA") || strings.Contains(match, "ASIA") {
		return "AWS"
	}
	if strings.Contains(match, "sk-") && strings.Contains(match, "T3BlbkFJ") {
		return "OpenAI"
	}
	if strings.Contains(match, "sk-ant-") {
		return "Anthropic"
	}
	if strings.HasPrefix(match, "ghp_") || strings.HasPrefix(match, "gho_") {
		return "GitHub"
	}
	if strings.HasPrefix(match, "sk_live_") {
		return "Stripe"
	}
	if strings.HasPrefix(match, "uzc") {
		return "Qiniu"
	}
	if strings.HasPrefix(match, "AC") && len(match) == 34 {
		return "Twilio"
	}
	if strings.HasPrefix(match, "xox") {
		return "Slack"
	}
	if strings.Contains(match, "cloudflare") {
		return "Cloudflare"
	}
	if strings.HasPrefix(match, "dop_v1_") {
		return "DigitalOcean"
	}
	if strings.HasPrefix(match, "SG.") {
		return "SendGrid"
	}
	if strings.Contains(match, "heroku") {
		return "Heroku"
	}

	for _, tag := range finding.Tags {
		switch strings.ToLower(tag) {
		case "aws":
			return "AWS"
		case "openai":
			return "OpenAI"
		case "github":
			return "GitHub"
		case "stripe":
			return "Stripe"
		case "slack":
			return "Slack"
		case "digitalocean":
			return "DigitalOcean"
		case "twilio":
			return "Twilio"
		case "cloudflare":
			return "Cloudflare"
		case "sendgrid":
			return "SendGrid"
		case "heroku":
			return "Heroku"
		case "qiniu":
			return "Qiniu"
		case "anthropic":
			return "Anthropic"
		}
	}

	return finding.RuleName
}

func extractSecretValue(finding models.Finding) string {
	match := finding.Match

	patterns := []string{
		`['"]([^'"]+)['"]`,
		`:\s*([^:\s]+)`,
		`=\s*([^;\s]+)`,
	}

	for _, pattern := range patterns {
		parts := strings.Split(match, pattern)
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}

	return match
}

func (v *Validator) validateAWS(accessKey, secretKey string) (bool, error) {
	return false, fmt.Errorf("AWS validation requires secret key - only validate your own keys")
}

func (v *Validator) validateOpenAI(apiKey string) (bool, error) {
	req, err := http.NewRequest("GET", "https://api.openai.com/v1/models", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return true, nil
	}

	if resp.StatusCode == 401 {
		return false, fmt.Errorf("invalid API key")
	}

	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("API error: %s", string(body))
}

func (v *Validator) validateAnthropic(apiKey string) (bool, error) {
	jsonData := `{"model":"claude-3-5-sonnet-20241022","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBufferString(jsonData))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return true, nil
	}

	if resp.StatusCode == 401 {
		return false, fmt.Errorf("invalid API key")
	}

	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("API error: %s", string(body))
}

func (v *Validator) validateGitHub(token string) (bool, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "token "+token)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return true, nil
	}

	if resp.StatusCode == 401 {
		return false, fmt.Errorf("invalid token")
	}

	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("API error: %s", string(body))
}

func (v *Validator) validateStripe(apiKey string) (bool, error) {
	req, err := http.NewRequest("GET", "https://api.stripe.com/v1/balance", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(apiKey, "")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return true, nil
	}

	if resp.StatusCode == 401 {
		return false, fmt.Errorf("invalid API key")
	}

	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("API error: %s", string(body))
}

func (v *Validator) validateQiniu(accessKey, secretKey string) (bool, error) {
	return false, fmt.Errorf("Qiniu validation requires both access key and secret key")
}

func (v *Validator) validateTwilio(sid, authToken string) (bool, error) {
	req, err := http.NewRequest("GET", "https://api.twilio.com/2010-01-01/Accounts/"+sid+".json", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(sid, authToken)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return true, nil
	}

	if resp.StatusCode == 401 {
		return false, fmt.Errorf("invalid credentials")
	}

	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("API error: %s", string(body))
}

func (v *Validator) validateSlack(token string) (bool, error) {
	req, err := http.NewRequest("GET", "https://slack.com/api/auth.test", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	if ok, exists := result["ok"]; exists {
		if okBool, ok := ok.(bool); okBool && ok {
			return true, nil
		}
	}

	if strings.Contains(string(body), "invalid_auth") {
		return false, fmt.Errorf("invalid token")
	}

	return false, fmt.Errorf("API error: %s", string(body))
}

func (v *Validator) validateCloudflare(apiKey string) (bool, error) {
	req, err := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return true, nil
	}

	if resp.StatusCode == 401 {
		return false, fmt.Errorf("invalid API token")
	}

	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("API error: %s", string(body))
}

func (v *Validator) validateDigitalOcean(token string) (bool, error) {
	req, err := http.NewRequest("GET", "https://api.digitalocean.com/v2/account", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return true, nil
	}

	if resp.StatusCode == 401 {
		return false, fmt.Errorf("invalid token")
	}

	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("API error: %s", string(body))
}

func (v *Validator) validateSendGrid(apiKey string) (bool, error) {
	req, err := http.NewRequest("GET", "https://api.sendgrid.com/v3/settings", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return true, nil
	}

	if resp.StatusCode == 401 {
		return false, fmt.Errorf("invalid API key")
	}

	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("API error: %s", string(body))
}

func (v *Validator) validateHeroku(apiKey string) (bool, error) {
	req, err := http.NewRequest("GET", "https://api.heroku.com/account", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/vnd.heroku+json; version=3")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return true, nil
	}

	if resp.StatusCode == 401 {
		return false, fmt.Errorf("invalid API key")
	}

	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("API error: %s", string(body))
}