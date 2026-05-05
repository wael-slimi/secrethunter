package models

type Config struct {
	OpenAIKey     string `json:"openai_key"`
	AnthropicKey  string `json:"anthropic_key"`
	OllamaURL     string `json:"ollama_url"`
	OllamaModel   string `json:"ollama_model"`
	DefaultAI     string `json:"default_ai"`
	GitleaksPath  string `json:"gitleaks_path"`
	ScanDepth     int    `json:"scan_depth"`
	OutputFormat  string `json:"output_format"`
}

func DefaultConfig() *Config {
	return &Config{
		OllamaURL:    "http://localhost:11434",
		OllamaModel:  "llama3",
		DefaultAI:    "openai",
		ScanDepth:    50,
		OutputFormat: "cli",
	}
}