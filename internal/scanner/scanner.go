package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"secrethunter/internal/models"
)

type Scanner struct {
	rules []Rule
}

type Rule struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Severity    models.Severity
	Tags        []string
	Service     string
	Description string
}

type GitleaksResult struct {
	Line       string   `json:"Line"`
	LineNumber int      `json:"LineNumber"`
	Match      string   `json:"Match"`
	File       string   `json:"File"`
	RuleID     string   `json:"RuleID"`
	Commit     string   `json:"Commit"`
	Entropy    float64  `json:"Entropy"`
	Tags       []string `json:"Tags"`
}

func NewScanner() *Scanner {
	return &Scanner{
		rules: loadRules(),
	}
}

func loadRules() []Rule {
	return []Rule{
		// AWS Credentials
		{"aws-access-key", "AWS Access Key ID", regexp.MustCompile(`\b(AKIA|ASIA|AROA|AIDA|ACCA|ABIA)[A-Z0-9]{16}\b`), models.SeverityCritical, []string{"aws", "cloud"}, "AWS", "AWS Access Key ID"},
		{"aws-secret-key", "AWS Secret Access Key", regexp.MustCompile(`(?i)aws(.{0,20})?(secret|private)(.{0,20})?['""]?([A-Za-z0-9/+=]{40})['""]?`), models.SeverityCritical, []string{"aws", "cloud"}, "AWS", "AWS Secret Access Key"},
		{"aws-mws-token", "AWS MWS Token", regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), models.SeverityCritical, []string{"aws", "mws"}, "AWS", "Amazon MWS Auth Token"},
		{"aws-appsync-key", "AWS AppSync API Key", regexp.MustCompile(`da2-[a-zA-Z0-9]{26}`), models.SeverityHigh, []string{"aws", "appsync"}, "AWS", "AWS AppSync API Key"},
		{"aws-sts-session", "AWS STS Session Token", regexp.MustCompile(`(?i)aws_session_token[=\s]+['"]?([A-Za-z0-9/+=]{200,400})['"]?`), models.SeverityHigh, []string{"aws", "sts"}, "AWS", "AWS STS Session Token"},

		// Google Cloud
		{"google-api-key", "Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), models.SeverityCritical, []string{"google", "cloud"}, "Google", "Google API Key"},
		{"google-oauth", "Google OAuth Token", regexp.MustCompile(`ya29\.[A-Za-z0-9\-_]+`), models.SeverityCritical, []string{"google", "oauth"}, "Google", "Google OAuth Access Token"},
		{"google-client-secret", "Google OAuth Client Secret", regexp.MustCompile(`GOCSPX-[A-Za-z0-9\-_]{28}`), models.SeverityCritical, []string{"google", "oauth"}, "Google", "Google OAuth Client Secret"},
		{"google-client-id", "Google OAuth Client ID", regexp.MustCompile(`[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com`), models.SeverityMedium, []string{"google", "oauth"}, "Google", "Google OAuth Client ID"},
		{"google-firebase-key", "Firebase Cloud Messaging Key", regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`), models.SeverityHigh, []string{"google", "firebase"}, "Google", "Firebase FCM Server Key"},
		{"google-recaptcha", "Google reCAPTCHA Key", regexp.MustCompile(`6L[0-9A-Za-z\-_]{38}|6[0-9a-zA-Z\-_]{39}`), models.SeverityMedium, []string{"google", "recaptcha"}, "Google", "Google reCAPTCHA"},

		// Azure
		{"azure-storage-conn", "Azure Storage Connection String", regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=[a-z0-9]{3,24};AccountKey=[A-Za-z0-9/+=]{88}==`), models.SeverityCritical, []string{"azure", "storage"}, "Azure", "Azure Storage Connection String"},
		{"azure-client-secret", "Azure Client Secret", regexp.MustCompile(`(?i)(client[_-]?secret|app[_-]?secret|tenant[_-]?secret)[=\s]+['"]?([A-Za-z0-9~]{30,})['"]?`), models.SeverityCritical, []string{"azure", "entra"}, "Azure", "Azure AD/Entra Client Secret"},
		{"azure-devops-pat", "Azure DevOps PAT", regexp.MustCompile(`[A-Za-z0-9]{52}AZDO[A-Za-z0-9]{4}`), models.SeverityCritical, []string{"azure", "devops"}, "Azure", "Azure DevOps Personal Access Token"},
		{"azure-storage-key", "Azure Storage Account Key", regexp.MustCompile(`(?i)accountkey[=\s]+['"]?([A-Za-z0-9/+=]{86,88})['"]?`), models.SeverityHigh, []string{"azure", "storage"}, "Azure", "Azure Storage Account Key"},
		{"azure-sas-token", "Azure SAS Token", regexp.MustCompile(`\?sv=[A-Za-z0-9\-_]{3,20}&sig=[A-Za-z0-9%]{30,}`), models.SeverityMedium, []string{"azure", "storage"}, "Azure", "Azure SAS Token"},
		{"azure-cosmos-db", "Azure Cosmos DB Connection", regexp.MustCompile(`AccountEndpoint=https://[a-z0-9\-]+\.documents\.azure\.com;AccountKey=[A-Za-z0-9/+=]{86,88}`), models.SeverityCritical, []string{"azure", "cosmos"}, "Azure", "Azure Cosmos DB Connection String"},
		{"azure-sql-conn", "Azure SQL Connection String", regexp.MustCompile(`Server=tcp:[a-z0-9\-]+\.database\.windows\.net;.*Password=[^;]{8,}`), models.SeverityCritical, []string{"azure", "sql"}, "Azure", "Azure SQL Connection String"},
		{"azure-service-bus", "Azure Service Bus Connection", regexp.MustCompile(`Endpoint=sb://[a-z0-9\-]+\.servicebus\.windows\.net/;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9/+=]{43}`), models.SeverityHigh, []string{"azure", "servicebus"}, "Azure", "Azure Service Bus Connection"},

		// Alibaba Cloud
		{"aliyun-access-key", "Aliyun Access Key ID", regexp.MustCompile(`LTAI[A-Za-z0-9]{20}`), models.SeverityCritical, []string{"aliyun", "alibaba"}, "Alibaba", "Alibaba Cloud Access Key ID"},
		{"aliyun-secret-key", "Aliyun Secret Key", regexp.MustCompile(`(?i)aliyun(.{0,20})?secret[=\s]+['"]?([A-Za-z0-9/+=]{30})['"]?`), models.SeverityCritical, []string{"aliyun", "alibaba"}, "Alibaba", "Alibaba Cloud Secret Key"},

		// Tencent Cloud
		{"tencent-secret-id", "Tencent Cloud Secret ID", regexp.MustCompile(`(?i)tencent(.{0,20})?(secret[_-]?id|secretid)[=\s]+['"]?([A-Za-z0-9]{20,})['"]?`), models.SeverityCritical, []string{"tencent", "qcloud"}, "Tencent", "Tencent Cloud Secret ID"},
		{"tencent-secret-key", "Tencent Cloud Secret Key", regexp.MustCompile(`(?i)tencent(.{0,20})?secret[_-]?key[=\s]+['"]?([A-Za-z0-9]{32,})['"]?`), models.SeverityCritical, []string{"tencent", "qcloud"}, "Tencent", "Tencent Cloud Secret Key"},

		// Qiniu (Chinese Cloud Storage)
		{"qiniu-access-key", "Qiniu Access Key", regexp.MustCompile(`uzc[A-Za-z0-9]{20}`), models.SeverityCritical, []string{"qiniu", "cloud"}, "Qiniu", "Qiniu Access Key"},
		{"qiniu-secret-key", "Qiniu Secret Key", regexp.MustCompile(`-[A-Za-z0-9]{30}`), models.SeverityMedium, []string{"qiniu", "cloud"}, "Qiniu", "Qiniu Secret Key"},

		// DigitalOcean
		{"digitalocean-token", "DigitalOcean Access Token", regexp.MustCompile(`dop_v1_[a-f0-9]{64}`), models.SeverityCritical, []string{"digitalocean", "cloud"}, "DigitalOcean", "DigitalOcean Access Token"},
		{"digitalocean-oauth", "DigitalOcean OAuth Token", regexp.MustCompile(`doo_v1_[a-f0-9]{64}`), models.SeverityCritical, []string{"digitalocean", "oauth"}, "DigitalOcean", "DigitalOcean OAuth Token"},
		{"digitalocean-refresh", "DigitalOcean Refresh Token", regexp.MustCompile(`dor_v1_[a-f0-9]{64}`), models.SeverityHigh, []string{"digitalocean", "oauth"}, "DigitalOcean", "DigitalOcean Refresh Token"},

		// Cloudflare
		{"cloudflare-api-key", "Cloudflare API Key", regexp.MustCompile(`(?i)cloudflare(.{0,20})?['"]([a-z0-9]{37})['"]`), models.SeverityCritical, []string{"cloudflare", "cdn"}, "Cloudflare", "Cloudflare API Key"},
		{"cloudflare-origin-ca", "Cloudflare Origin CA Key", regexp.MustCompile(`v1\.0-[a-f0-9]{24}-[a-f0-9]{146}`), models.SeverityHigh, []string{"cloudflare", "cdn"}, "Cloudflare", "Cloudflare Origin CA Key"},
		{"cloudflare-api-token", "Cloudflare API Token", regexp.MustCompile(`(?i)cloudflare[_-]?token[=\s]+['"]?([A-Za-z0-9\-_]{40,})['"]?`), models.SeverityHigh, []string{"cloudflare", "cdn"}, "Cloudflare", "Cloudflare API Token"},

		// OpenAI & AI Services
		{"openai-api-key", "OpenAI API Key", regexp.MustCompile(`sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`), models.SeverityCritical, []string{"openai", "ai"}, "OpenAI", "OpenAI API Key"},
		{"openai-project-key", "OpenAI Project API Key", regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{80,}`), models.SeverityCritical, []string{"openai", "ai"}, "OpenAI", "OpenAI Project API Key"},
		{"openai-org-key", "OpenAI Organization Key", regexp.MustCompile(`org-[A-Za-z0-9]{20,}`), models.SeverityMedium, []string{"openai", "ai"}, "OpenAI", "OpenAI Organization ID"},
		{"anthropic-api-key", "Anthropic API Key", regexp.MustCompile(`sk-ant-api03-[A-Za-z0-9\-_]{80,}`), models.SeverityCritical, []string{"anthropic", "ai"}, "Anthropic", "Anthropic API Key"},
		{"huggingface-token", "Hugging Face Access Token", regexp.MustCompile(`hf_[A-Za-z0-9]{34}`), models.SeverityCritical, []string{"huggingface", "ai"}, "HuggingFace", "Hugging Face Access Token"},
		{"huggingface-org-token", "Hugging Face Org Token", regexp.MustCompile(`api_org_[A-Za-z0-9]{34}`), models.SeverityCritical, []string{"huggingface", "ai"}, "HuggingFace", "Hugging Face Org API Token"},
		{"replicate-token", "Replicate API Token", regexp.MustCompile(`r8_[A-Za-z0-9]{36}`), models.SeverityHigh, []string{"replicate", "ai"}, "Replicate", "Replicate API Token"},
		{"perplexity-api-key", "Perplexity API Key", regexp.MustCompile(`pplx-[A-Za-z0-9]{48}`), models.SeverityHigh, []string{"perplexity", "ai"}, "Perplexity", "Perplexity API Key"},
		{"cohere-api-key", "Cohere API Key", regexp.MustCompile(`(?i)cohere(.{0,20})?['"]([A-Za-z0-9\-_]{40,})['"]`), models.SeverityHigh, []string{"cohere", "ai"}, "Cohere", "Cohere API Key"},

		// GitHub
		{"github-token", "GitHub Personal Access Token", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), models.SeverityCritical, []string{"github", "git"}, "GitHub", "GitHub Personal Access Token"},
		{"github-oauth", "GitHub OAuth Token", regexp.MustCompile(`gho_[A-Za-z0-9]{36}`), models.SeverityCritical, []string{"github", "oauth"}, "GitHub", "GitHub OAuth Token"},
		{"github-app-token", "GitHub App Token", regexp.MustCompile(`(ghu|ghs|ghr)_[A-Za-z0-9]{36}`), models.SeverityCritical, []string{"github", "app"}, "GitHub", "GitHub App Token"},
		{"github-action-token", "GitHub Actions Token", regexp.MustCompile(`(?i)gha_[a-z0-9]{36}`), models.SeverityHigh, []string{"github", "actions"}, "GitHub", "GitHub Actions Token"},
		{"github-deploy-key", "GitHub Deploy Key", regexp.MustCompile(`(?i)github(.{0,20})?deploy[_-]?key[=\s]+['"]?([A-Za-z0-9\-_]{20,})['"]?`), models.SeverityMedium, []string{"github", "deploy"}, "GitHub", "GitHub Deploy Key"},

		// GitLab
		{"gitlab-pat", "GitLab Personal Access Token", regexp.MustCompile(`glpat-[A-Za-z0-9\-_]{20}`), models.SeverityCritical, []string{"gitlab", "git"}, "GitLab", "GitLab Personal Access Token"},
		{"gitlab-oauth", "GitLab OAuth Token", regexp.MustCompile(`(?i)gitlab(.{0,20})?oauth[_-]?token[=\s]+['"]?([A-Za-z0-9\-_]{20,})['"]?`), models.SeverityHigh, []string{"gitlab", "oauth"}, "GitLab", "GitLab OAuth Token"},
		{"gitlab-ci-token", "GitLab CI Token", regexp.MustCompile(`(?i)gitlab(.{0,20})?ci[_-]?token[=\s]+['"]?([A-Za-z0-9\-_]{20,})['"]?`), models.SeverityHigh, []string{"gitlab", "ci"}, "GitLab", "GitLab CI Token"},
		{"gitlab-runner-token", "GitLab Runner Token", regexp.MustCompile(`(?i)gitlab(.{0,20})?runner[_-]?token[=\s]+['"]?([A-Za-z0-9\-_]{20,})['"]?`), models.SeverityMedium, []string{"gitlab", "runner"}, "GitLab", "GitLab Runner Registration Token"},

		// Bitbucket
		{"bitbucket-token", "Bitbucket App Password", regexp.MustCompile(`(?i)bitbucket(.{0,20})?['"]([A-Za-z0-9]{16,})['"]`), models.SeverityHigh, []string{"bitbucket", "git"}, "Bitbucket", "Bitbucket App Password"},
		{"bitbucket-oauth", "Bitbucket OAuth Token", regexp.MustCompile(`(?i)bitbucket(.{0,20})?oauth[_-]?token[=\s]+['"]?([A-Za-z0-9\-_]{40,})['"]?`), models.SeverityHigh, []string{"bitbucket", "oauth"}, "Bitbucket", "Bitbucket OAuth Token"},

		// Slack
		{"slack-bot-token", "Slack Bot Token", regexp.MustCompile(`xoxb-[0-9A-Za-z]{10,48}`), models.SeverityCritical, []string{"slack", "chat"}, "Slack", "Slack Bot Token"},
		{"slack-user-token", "Slack User Token", regexp.MustCompile(`xoxp-[0-9A-Za-z]{10,48}`), models.SeverityCritical, []string{"slack", "chat"}, "Slack", "Slack User Token"},
		{"slack-workspace-token", "Slack Workspace Token", regexp.MustCompile(`xoxa-[0-9A-Za-z]{10,48}`), models.SeverityHigh, []string{"slack", "chat"}, "Slack", "Slack Workspace Token"},
		{"slack-app-token", "Slack App Token", regexp.MustCompile(`xoxa-[0-9A-Za-z]{10,48}`), models.SeverityHigh, []string{"slack", "chat"}, "Slack", "Slack App Token"},
		{"slack-webhook", "Slack Webhook URL", regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}`), models.SeverityMedium, []string{"slack", "webhook"}, "Slack", "Slack Incoming Webhook"},

		// Discord
		{"discord-bot-token", "Discord Bot Token", regexp.MustCompile(`[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}`), models.SeverityCritical, []string{"discord", "chat"}, "Discord", "Discord Bot Token"},
		{"discord-firebase-key", "Discord Firebase Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), models.SeverityMedium, []string{"discord", "firebase"}, "Discord", "Discord Firebase Key"},

		// Telegram
		{"telegram-bot-token", "Telegram Bot Token", regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9_-]{35}`), models.SeverityHigh, []string{"telegram", "chat"}, "Telegram", "Telegram Bot Token"},
		{"telegram-api-hash", "Telegram API Hash", regexp.MustCompile(`(?i)telegram(.{0,20})?api[_-]?hash[=\s]+['"]?([a-z0-9]{32})['"]?`), models.SeverityMedium, []string{"telegram", "api"}, "Telegram", "Telegram API Hash"},

		// Twilio
		{"twilio-account-sid", "Twilio Account SID", regexp.MustCompile(`AC[a-zA-Z0-9]{32}`), models.SeverityHigh, []string{"twilio", "sms"}, "Twilio", "Twilio Account SID"},
		{"twilio-auth-token", "Twilio Auth Token", regexp.MustCompile(`(?i)twilio(.{0,20})?auth[_-]?token[=\s]+['"]?([a-zA-Z0-9]{32})['"]?`), models.SeverityHigh, []string{"twilio", "sms"}, "Twilio", "Twilio Auth Token"},
		{"twilio-api-key", "Twilio API Key", regexp.MustCompile(`SK[a-fA-F0-9]{32}`), models.SeverityHigh, []string{"twilio", "sms"}, "Twilio", "Twilio API Key SID"},

		// Stripe
		{"stripe-secret-key", "Stripe Secret Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), models.SeverityCritical, []string{"stripe", "payment"}, "Stripe", "Stripe Secret Key"},
		{"stripe-publishable-key", "Stripe Publishable Key", regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`), models.SeverityMedium, []string{"stripe", "payment"}, "Stripe", "Stripe Publishable Key"},
		{"stripe-restricted-key", "Stripe Restricted Key", regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24,}`), models.SeverityHigh, []string{"stripe", "payment"}, "Stripe", "Stripe Restricted Key"},
		{"stripe-webhook-secret", "Stripe Webhook Secret", regexp.MustCompile(`whsec_[A-Za-z0-9]{32}`), models.SeverityHigh, []string{"stripe", "webhook"}, "Stripe", "Stripe Webhook Secret"},

		// PayPal
		{"paypal-access-token", "PayPal Access Token", regexp.MustCompile(`access_token\$production\${0,1}[a-zA-Z0-9]{16}\${0,1}[a-zA-Z0-9]{32}`), models.SeverityHigh, []string{"paypal", "payment"}, "PayPal", "PayPal Access Token"},
		{"paypal-client-secret", "PayPal Client Secret", regexp.MustCompile(`(?i)paypal(.{0,20})?client[_-]?secret[=\s]+['"]?([A-Za-z0-9\-_]{40,})['"]?`), models.SeverityCritical, []string{"paypal", "payment"}, "PayPal", "PayPal Client Secret"},

		// Square
		{"square-access-token", "Square Access Token", regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`), models.SeverityHigh, []string{"square", "payment"}, "Square", "Square Access Token"},
		{"square-oauth-secret", "Square OAuth Secret", regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}`), models.SeverityHigh, []string{"square", "oauth"}, "Square", "Square OAuth Secret"},

		// SendGrid
		{"sendgrid-api-key", "SendGrid API Key", regexp.MustCompile(`SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{22,}`), models.SeverityCritical, []string{"sendgrid", "email"}, "SendGrid", "SendGrid API Key"},
		{"sendgrid-api-key-alt", "SendGrid API Key (Alt)", regexp.MustCompile(`(?i)sendgrid(.{0,20})?api[_-]?key[=\s]+['"]?([A-Za-z0-9\-_]{20,})['"]?`), models.SeverityCritical, []string{"sendgrid", "email"}, "SendGrid", "SendGrid API Key"},

		// Mailgun
		{"mailgun-api-key", "Mailgun API Key", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`), models.SeverityCritical, []string{"mailgun", "email"}, "Mailgun", "Mailgun API Key"},
		{"mailgun-private-api", "Mailgun Private API Key", regexp.MustCompile(`(?i)mailgun(.{0,20})?private[_-]?api[_-]?key[=\s]+['"]?([a-z0-9]{32})['"]?`), models.SeverityHigh, []string{"mailgun", "email"}, "Mailgun", "Mailgun Private API Key"},

		// Postmark
		{"postmark-api-key", "Postmark API Key", regexp.MustCompile(`(?i)postmark(.{0,20})?['"]([a-z0-9]{32})['"]`), models.SeverityHigh, []string{"postmark", "email"}, "Postmark", "Postmark API Key"},

		// Mailchimp
		{"mailchimp-api-key", "Mailchimp API Key", regexp.MustCompile(`[a-f0-9]{32}-us[0-9]{1,2}`), models.SeverityHigh, []string{"mailchimp", "email"}, "Mailchimp", "Mailchimp API Key"},
		{"mailchimp-oauth", "Mailchimp OAuth Token", regexp.MustCompile(`(?i)mailchimp(.{0,20})?oauth[_-]?token[=\s]+['"]?([A-Za-z0-9\-_]{20,})['"]?`), models.SeverityHigh, []string{"mailchimp", "email"}, "Mailchimp", "Mailchimp OAuth Token"},

		// AWS SES
		{"aws-ses-smtp", "AWS SES SMTP Password", regexp.MustCompile(`(?i)ses(.{0,20})?smtp(.{0,20})?password[=\s]+['"]?([A-Za-z0-9]{44})['"]?`), models.SeverityHigh, []string{"aws", "ses", "email"}, "AWS", "AWS SES SMTP Password"},

		// Database Connection Strings
		{"mongodb-conn", "MongoDB Connection String", regexp.MustCompile(`mongodb(\+srv)?://[^:]+:[^@]+@`), models.SeverityCritical, []string{"mongodb", "database"}, "MongoDB", "MongoDB Connection String"},
		{"postgres-conn", "PostgreSQL Connection String", regexp.MustCompile(`postgresql://[^:]+:[^@]+@`), models.SeverityCritical, []string{"postgresql", "database"}, "PostgreSQL", "PostgreSQL Connection String"},
		{"mysql-conn", "MySQL Connection String", regexp.MustCompile(`mysql://[^:]+:[^@]+@`), models.SeverityCritical, []string{"mysql", "database"}, "MySQL", "MySQL Connection String"},
		{"redis-conn", "Redis Connection String", regexp.MustCompile(`redis://[^:]+:[^@]+@`), models.SeverityHigh, []string{"redis", "database"}, "Redis", "Redis Connection String"},
		{"mssql-conn", "MSSQL Connection String", regexp.MustCompile(`Server=[^;]+;.*Password=[^;]{8,}`), models.SeverityCritical, []string{"mssql", "database"}, "MSSQL", "MSSQL Connection String"},
		{"oracle-conn", "Oracle Connection String", regexp.MustCompile(`(?i)oracle(.{0,20})?(connection|string)[=\s]+['"]?([^'"]{20,})['"]?`), models.SeverityCritical, []string{"oracle", "database"}, "Oracle", "Oracle Connection String"},

		// Firebase
		{"firebase-url", "Firebase URL", regexp.MustCompile(`https://[a-z0-9\-]+\.firebaseio\.com`), models.SeverityMedium, []string{"firebase", "database"}, "Firebase", "Firebase Database URL"},
		{"firebase-config", "Firebase Config JSON", regexp.MustCompile(`"type"\s*:\s*"service_account"`), models.SeverityCritical, []string{"firebase", "config"}, "Firebase", "Firebase Service Account Config"},
		{"firebase-api-key", "Firebase API Key", regexp.MustCompile(`(?i)firebase(.{0,20})?api[_-]?key[=\s]+['"]?([A-Za-z0-9\-_]{30,})['"]?`), models.SeverityHigh, []string{"firebase", "api"}, "Firebase", "Firebase API Key"},

		// Heroku
		{"heroku-api-key", "Heroku API Key", regexp.MustCompile(`[hH][eE][rR][oO][kK][uU][a-zA-Z0-9]{32}`), models.SeverityCritical, []string{"heroku", "paas"}, "Heroku", "Heroku API Key"},
		{"heroku-oauth-token", "Heroku OAuth Token", regexp.MustCompile(`(?i)heroku(.{0,20})?oauth[_-]?token[=\s]+['"]?([A-Za-z0-9\-_]{30,})['"]?`), models.SeverityHigh, []string{"heroku", "oauth"}, "Heroku", "Heroku OAuth Token"},

		// Docker
		{"docker-hub-password", "Docker Hub Password", regexp.MustCompile(`(?i)docker(.{0,20})?password[=\s]+['"]?([A-Za-z0-9\-_]{8,})['"]?`), models.SeverityHigh, []string{"docker", "registry"}, "Docker", "Docker Hub Password"},
		{"docker-config-auth", "Docker Config Auth", regexp.MustCompile(`"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"`), models.SeverityHigh, []string{"docker", "registry"}, "Docker", "Docker Config Authentication"},
		{"dockerconfig-json", "Dockerconfig JSON", regexp.MustCompile(`(?i)dockerconfig[_-]?json[=\s]*['"]?\{`), models.SeverityHigh, []string{"docker", "registry"}, "Docker", "Dockerconfig JSON Content"},

		// NPM/Node.js
		{"npm-access-token", "NPM Access Token", regexp.MustCompile(`npm_[A-Za-z0-9]{36}`), models.SeverityCritical, []string{"npm", "package"}, "NPM", "NPM Access Token"},
		{"pypi-token", "PyPI API Token", regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}`), models.SeverityCritical, []string{"pypi", "package"}, "PyPI", "PyPI API Token"},

		// HashiCorp
		{"vault-token", "HashiCorp Vault Token", regexp.MustCompile(`hvs\.[A-Za-z0-9\-_]{90,120}`), models.SeverityCritical, []string{"vault", "secrets"}, "HashiCorp", "HashiCorp Vault Token"},
		{"vault-password", "HashiCorp Vault Password", regexp.MustCompile(`(?i)vault(.{0,20})?(password|secret)[=\s]+['"]?([A-Za-z0-9\-_]{20,})['"]?`), models.SeverityHigh, []string{"vault", "secrets"}, "HashiCorp", "HashiCorp Vault Password"},
		{"terraform-token", "Terraform Token", regexp.MustCompile(`(?i)terraform(.{0,20})?(token|api[_-]?key)[=\s]+['"]?([A-Za-z0-9\-_]{20,})['"]?`), models.SeverityHigh, []string{"terraform", "infra"}, "Terraform", "Terraform Cloud Token"},

		// Datadog
		{"datadog-api-key", "Datadog API Key", regexp.MustCompile(`(?i)datadog(.{0,20})?api[_-]?key[=\s]+['"]?([a-f0-9]{32})['"]?`), models.SeverityHigh, []string{"datadog", "monitoring"}, "Datadog", "Datadog API Key"},
		{"datadog-app-key", "Datadog Application Key", regexp.MustCompile(`(?i)datadog(.{0,20})?app[_-]?key[=\s]+['"]?([a-f0-9]{32})['"]?`), models.SeverityHigh, []string{"datadog", "monitoring"}, "Datadog", "Datadog Application Key"},

		// Sentry
		{"sentry-org-token", "Sentry Organization Token", regexp.MustCompile(`sntrys_eyJpYXQiO[A-Za-z0-9_-]{50,}`), models.SeverityHigh, []string{"sentry", "monitoring"}, "Sentry", "Sentry Organization Token"},
		{"sentry-user-token", "Sentry User Token", regexp.MustCompile(`sntryu_[A-Za-z0-9]{64}`), models.SeverityHigh, []string{"sentry", "monitoring"}, "Sentry", "Sentry User Token"},
		{"sentry-dsn", "Sentry DSN", regexp.MustCompile(`https://[a-f0-9]{32}@sentry\.io/[0-9]+`), models.SeverityLow, []string{"sentry", "monitoring"}, "Sentry", "Sentry DSN"},

		// New Relic
		{"newrelic-api-key", "New Relic API Key", regexp.MustCompile(`NRAK-[A-Za-z0-9]{27}`), models.SeverityHigh, []string{"newrelic", "monitoring"}, "NewRelic", "New Relic User API Key"},
		{"newrelic-insert-key", "New Relic Insert Key", regexp.MustCompile(`NRII-[A-Za-z0-9]{32}`), models.SeverityHigh, []string{"newrelic", "monitoring"}, "NewRelic", "New Relic Insert Key"},
		{"newrelic-browser-token", "New Relic Browser Token", regexp.MustCompile(`NRJS-[A-Za-z0-9]{19}`), models.SeverityMedium, []string{"newrelic", "monitoring"}, "NewRelic", "New Relic Browser API Token"},

		// Dynatrace
		{"dynatrace-api-token", "Dynatrace API Token", regexp.MustCompile(`dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}`), models.SeverityHigh, []string{"dynatrace", "monitoring"}, "Dynatrace", "Dynatrace API Token"},

		// Grafana
		{"grafana-api-key", "Grafana API Key", regexp.MustCompile(`(?i)grafana(.{0,20})?api[_-]?key[=\s]+['"]?([A-Za-z0-9]{30})['"]?`), models.SeverityHigh, []string{"grafana", "monitoring"}, "Grafana", "Grafana API Key"},
		{"grafana-service-account", "Grafana Service Account Token", regexp.MustCompile(`glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}`), models.SeverityHigh, []string{"grafana", "monitoring"}, "Grafana", "Grafana Service Account Token"},

		// Shopify
		{"shopify-access-token", "Shopify Access Token", regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`), models.SeverityCritical, []string{"shopify", "ecommerce"}, "Shopify", "Shopify Access Token"},
		{"shopify-api-key", "Shopify API Key", regexp.MustCompile(`(?i)shopify(.{0,20})?api[_-]?key[=\s]+['"]?([a-z0-9]{20,})['"]?`), models.SeverityHigh, []string{"shopify", "ecommerce"}, "Shopify", "Shopify API Key"},

		// Linear
		{"linear-api-key", "Linear API Key", regexp.MustCompile(`lin_api_[A-Za-z0-9]{40}`), models.SeverityHigh, []string{"linear", "project"}, "Linear", "Linear API Key"},
		{"linear-webhook-secret", "Linear Webhook Secret", regexp.MustCompile(`(?i)linear(.{0,20})?webhook[_-]?secret[=\s]+['"]?([A-Za-z0-9\-_]{20,})['"]?`), models.SeverityMedium, []string{"linear", "project"}, "Linear", "Linear Webhook Secret"},

		// Notion
		{"notion-integration-token", "Notion Integration Token", regexp.MustCompile(`secret_[A-Za-z0-9]{48}`), models.SeverityHigh, []string{"notion", "productivity"}, "Notion", "Notion Integration Token"},

		// Zoom
		{"zoom-jwt-token", "Zoom JWT Token", regexp.MustCompile(`(?i)zoom(.{0,20})?jwt[_-]?token[=\s]+['"]?([A-Za-z0-9\-_.]{30,})['"]?`), models.SeverityMedium, []string{"zoom", "video"}, "Zoom", "Zoom JWT Token"},
		{"zoom-api-key", "Zoom API Key", regexp.MustCompile(`(?i)zoom(.{0,20})?api[_-]?key[=\s]+['"]?([A-Za-z0-9]{20,})['"]?`), models.SeverityMedium, []string{"zoom", "video"}, "Zoom", "Zoom API Key"},

		// Generic/API Keys
		{"generic-api-key", "Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?key)[=\s]+['"]?([A-Za-z0-9\-_]{20,})['"]?`), models.SeverityMedium, []string{"generic", "api"}, "Generic", "Generic API Key"},
		{"generic-secret", "Generic Secret", regexp.MustCompile(`(?i)(secret[_-]?key|secret[_-]?token|client[_-]?secret)[=\s]+['"]?([A-Za-z0-9\-_]{16,})['"]?`), models.SeverityMedium, []string{"generic", "secret"}, "Generic", "Generic Secret"},
		{"generic-password", "Generic Password", regexp.MustCompile(`(?i)(password|passwd|pwd)[=\s]+['"]?([A-Za-z0-9\-_!@#$%^&*()]{6,})['"]?`), models.SeverityMedium, []string{"generic", "password"}, "Generic", "Generic Password"},
		{"generic-token", "Generic Token", regexp.MustCompile(`(?i)(auth[_-]?token|access[_-]?token|bearer[_-]?token)[=\s]+['"]?([A-Za-z0-9\-_]{20,})['"]?`), models.SeverityMedium, []string{"generic", "token"}, "Generic", "Generic Auth Token"},

		// Authorization Headers
		{"bearer-token", "Bearer Token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-_.~+/]{20,}`), models.SeverityMedium, []string{"auth", "bearer"}, "Generic", "Bearer Token"},
		{"basic-auth", "Basic Auth Header", regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9+/=]{20,}`), models.SeverityMedium, []string{"auth", "basic"}, "Generic", "HTTP Basic Authentication"},
		{"password-in-url", "Password in URL", regexp.MustCompile(`[a-zA-Z]{3,10}://[^/\\s:@]+:[^/\\s:@]+@[^\\s'"]{5,}`), models.SeverityHigh, []string{"auth", "url"}, "Generic", "Password Embedded in URL"},

		// JWT Tokens
		{"jwt-token", "JWT Token", regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`), models.SeverityMedium, []string{"jwt", "token"}, "JWT", "JSON Web Token"},
		{"jwt-secret", "JWT Secret", regexp.MustCompile(`(?i)(jwt[_-]?secret|jwt[_-]?key)[=\s]+['"]?([A-Za-z0-9\-_+=]{16,})['"]?`), models.SeverityHigh, []string{"jwt", "secret"}, "JWT", "JWT Secret"},

		// Private Keys
		{"rsa-private-key", "RSA Private Key", regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), models.SeverityCritical, []string{"crypto", "private-key"}, "Cryptographic", "RSA Private Key"},
		{"ec-private-key", "EC Private Key", regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), models.SeverityCritical, []string{"crypto", "private-key"}, "Cryptographic", "EC Private Key"},
		{"dsa-private-key", "DSA Private Key", regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`), models.SeverityCritical, []string{"crypto", "private-key"}, "Cryptographic", "DSA Private Key"},
		{"openssh-private-key", "OpenSSH Private Key", regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`), models.SeverityCritical, []string{"crypto", "private-key"}, "Cryptographic", "OpenSSH Private Key"},
		{"pgp-private-key", "PGP Private Key", regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), models.SeverityCritical, []string{"crypto", "private-key"}, "Cryptographic", "PGP Private Key"},
		{"private-key-header", "Private Key Header (Generic)", regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`), models.SeverityCritical, []string{"crypto", "private-key"}, "Cryptographic", "Generic Private Key"},

		// SSH Keys
		{"ssh-rsa-key", "SSH RSA Key", regexp.MustCompile(`ssh-rsa\s+[A-Za-z0-9+/=]{200,}`), models.SeverityHigh, []string{"ssh", "key"}, "SSH", "SSH RSA Key"},
		{"ssh-ed25519-key", "SSH ED25519 Key", regexp.MustCompile(`ssh-ed25519\s+[A-Za-z0-9+/=]{50,}`), models.SeverityHigh, []string{"ssh", "key"}, "SSH", "SSH ED25519 Key"},

		// Certificates
		{"private-cert", "Private Certificate", regexp.MustCompile(`-----BEGIN CERTIFICATE-----`), models.SeverityMedium, []string{"certificate", "tls"}, "Certificate", "Private Certificate"},
		{"pkcs12-key", "PKCS12 Keystore", regexp.MustCompile(`(?i)pkcs12[_-]?key[=\s]+['"]?([A-Za-z0-9+/=]{20,})['"]?`), models.SeverityHigh, []string{"certificate", "keystore"}, "Certificate", "PKCS12 Keystore Password"},

		// Environment Variables (common patterns)
		{"env-secret", "Environment Variable Secret", regexp.MustCompile(`(?i)(SECRET|PASSWORD|TOKEN|KEY|API_KEY|PRIVATE)[_\-]?(KEY|TOKEN|SECRET)?[=\s]+['"]?([A-Za-z0-9\-_+=]{8,})['"]?`), models.SeverityMedium, []string{"env", "secret"}, "Generic", "Environment Variable with Secret Value"},

		// Configuration Files
		{"ini-secret", "INI File Secret", regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)[=\s]+['"]?([A-Za-z0-9\-_]{10,})['"]?`), models.SeverityMedium, []string{"config", "ini"}, "Generic", "Secret in INI Configuration"},
		{"json-secret", "JSON Secret", regexp.MustCompile(`"(api[_-]?key|secret|password|token)"[:\s]+["'][^"']{10,}["']`), models.SeverityMedium, []string{"config", "json"}, "Generic", "Secret in JSON Configuration"},
		{"yaml-secret", "YAML Secret", regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)[:\s]+['"]?[A-Za-z0-9\-_]{10,}['"]?`), models.SeverityMedium, []string{"config", "yaml"}, "Generic", "Secret in YAML Configuration"},

		// Cloud Credentials Files
		{"aws-credentials-file", "AWS Credentials File", regexp.MustCompile(`(?i)\[default\][\s\S]*aws_access_key_id[\s=]+[A-Z0-9]{20}`), models.SeverityCritical, []string{"aws", "credentials"}, "AWS", "AWS Credentials File Content"},
		{"aws-config-file", "AWS Config File", regexp.MustCompile(`(?i)\[profile[\s\S]*region[\s=]+[a-z0-9-]+`), models.SeverityMedium, []string{"aws", "config"}, "AWS", "AWS Config File Content"},
		{"gcp-service-account", "GCP Service Account", regexp.MustCompile(`"type"\s*:\s*"service_account"`), models.SeverityCritical, []string{"gcp", "service-account"}, "Google", "Google Cloud Service Account JSON"},
		{"azure-key-vault", "Azure Key Vault Reference", regexp.MustCompile(`(?i)keyvault(.{0,20})?vault[_-]?uri[=\s]+['"]?https://[a-z0-9-]+\.vault\.azure\.net`), models.SeverityMedium, []string{"azure", "keyvault"}, "Azure", "Azure Key Vault URI"},

		// Credits Cards (Note: These are patterns for detection, not valid card numbers)
		{"credit-card-visa", "Potential Credit Card (Visa)", regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`), models.SeverityHigh, []string{"pii", "credit-card"}, "Generic", "Potential Visa Credit Card Number"},
		{"credit-card-mastercard", "Potential Credit Card (Mastercard)", regexp.MustCompile(`\b5[1-5][0-9]{14}\b`), models.SeverityHigh, []string{"pii", "credit-card"}, "Generic", "Potential Mastercard Number"},
		{"credit-card-amex", "Potential Credit Card (Amex)", regexp.MustCompile(`\b3[47][0-9]{13}\b`), models.SeverityHigh, []string{"pii", "credit-card"}, "Generic", "Potential American Express Card"},
		{"credit-card-discover", "Potential Credit Card (Discover)", regexp.MustCompile(`\b6(?:011|5[0-9]{2})[0-9]{12}\b`), models.SeverityHigh, []string{"pii", "credit-card"}, "Generic", "Potential Discover Card"},

		// Social Media Keys
		{"twitter-api-key", "Twitter API Key", regexp.MustCompile(`(?i)twitter(.{0,20})?api[_-]?key[=\s]+['"]?([A-Za-z0-9]{25,})['"]?`), models.SeverityHigh, []string{"twitter", "social"}, "Twitter", "Twitter API Key"},
		{"twitter-api-secret", "Twitter API Secret", regexp.MustCompile(`(?i)twitter(.{0,20})?api[_-]?secret[=\s]+['"]?([A-Za-z0-9]{25,})['"]?`), models.SeverityHigh, []string{"twitter", "social"}, "Twitter", "Twitter API Secret"},
		{"twitter-bearer-token", "Twitter Bearer Token", regexp.MustCompile(`(?i)twitter(.{0,20})?bearer[_-]?token[=\s]+['"]?([A-Za-z0-9]{50,})['"]?`), models.SeverityHigh, []string{"twitter", "social"}, "Twitter", "Twitter Bearer Token"},
		{"facebook-access-token", "Facebook Access Token", regexp.MustCompile(`EAACEdEose0cBA[A-Za-z0-9]+`), models.SeverityHigh, []string{"facebook", "social"}, "Facebook", "Facebook Access Token"},
		{"facebook-app-secret", "Facebook App Secret", regexp.MustCompile(`(?i)facebook(.{0,20})?app[_-]?secret[=\s]+['"]?([A-Za-z0-9]{32})['"]?`), models.SeverityHigh, []string{"facebook", "social"}, "Facebook", "Facebook App Secret"},

		// Box.com
		{"box-api-key", "Box API Key", regexp.MustCompile(`(?i)box(.{0,20})?api[_-]?key[=\s]+['"]?([A-Za-z0-9]{32})['"]?`), models.SeverityHigh, []string{"box", "storage"}, "Box", "Box API Key"},
		{"box-oauth", "Box OAuth Token", regexp.MustCompile(`(?i)box(.{0,20})?oauth[_-]?token[=\s]+['"]?([A-Za-z0-9\-_]{30,})['"]?`), models.SeverityHigh, []string{"box", "oauth"}, "Box", "Box OAuth Token"},

		// Dropbox
		{"dropbox-access-token", "Dropbox Access Token", regexp.MustCompile(`(?i)dropbox(.{0,20})?access[_-]?token[=\s]+['"]?([a-zA-Z0-9]{40,})['"]?`), models.SeverityHigh, []string{"dropbox", "storage"}, "Dropbox", "Dropbox Access Token"},
		{"dropbox-app-secret", "Dropbox App Secret", regexp.MustCompile(`(?i)dropbox(.{0,20})?app[_-]?secret[=\s]+['"]?([a-zA-Z0-9]{30,})['"]?`), models.SeverityHigh, []string{"dropbox", "storage"}, "Dropbox", "Dropbox App Secret"},

		// Kubeconfig
		{"kubeconfig", "Kubernetes Config", regexp.MustCompile(`(?i)kubeconfig[\s\S]*server:\s*https://`), models.SeverityHigh, []string{"kubernetes", "config"}, "Kubernetes", "Kubernetes Configuration File"},
		{"kubeconfig-token", "Kubernetes Service Account Token", regexp.MustCompile(`(?i)kubernetes(.{0,20})?token[=\s]+['"]?([A-Za-z0-9\-_/.]{30,})['"]?`), models.SeverityHigh, []string{"kubernetes", "token"}, "Kubernetes", "Kubernetes Service Account Token"},

		// S3 Bucket References (not credentials but sensitive)
		{"aws-s3-bucket", "AWS S3 Bucket URL", regexp.MustCompile(`s3\.amazonaws\.com/[a-z0-9\-\.]+`), models.SeverityLow, []string{"aws", "s3"}, "AWS", "AWS S3 Bucket Reference"},
		{"gcp-storage-bucket", "GCP Storage Bucket", regexp.MustCompile(`storage\.googleapis\.com/[a-z0-9\-\.]+`), models.SeverityLow, []string{"gcp", "storage"}, "Google", "GCP Storage Bucket Reference"},

		// Atlassian
		{"jira-api-token", "Jira API Token", regexp.MustCompile(`(?i)jira(.{0,20})?api[_-]?token[=\s]+['"]?([A-Za-z0-9]{24})['"]?`), models.SeverityHigh, []string{"jira", "atlassian"}, "Atlassian", "Jira API Token"},
		{"confluence-token", "Confluence Token", regexp.MustCompile(`(?i)confluence(.{0,20})?token[=\s]+['"]?([A-Za-z0-9]{24})['"]?`), models.SeverityHigh, []string{"confluence", "atlassian"}, "Atlassian", "Confluence API Token"},
		{"bitbucket-app-password", "Bitbucket App Password", regexp.MustCompile(`(?i)bitbucket(.{0,20})?app[_-]?password[=\s]+['"]?([A-Za-z0-9]{16})['"]?`), models.SeverityHigh, []string{"bitbucket", "atlassian"}, "Atlassian", "Bitbucket App Password"},

		// Contentful
		{"contentful-access-token", "Contentful Access Token", regexp.MustCompile(`(?i)contentful(.{0,20})?access[_-]?token[=\s]+['"]?([A-Za-z0-9\-_]{43})['"]?`), models.SeverityHigh, []string{"contentful", "cms"}, "Contentful", "Contentful Access Token"},
		{"contentful-delivery-token", "Contentful Delivery Token", regexp.MustCompile(`(?i)contentful(.{0,20})?delivery[_-]?token[=\s]+['"]?([A-Za-z0-9\-_]{43})['"]?`), models.SeverityMedium, []string{"contentful", "cms"}, "Contentful", "Contentful Delivery Token"},

		// Auth0
		{"auth0-client-secret", "Auth0 Client Secret", regexp.MustCompile(`(?i)auth0(.{0,20})?client[_-]?secret[=\s]+['"]?([A-Za-z0-9\-_]{30,})['"]?`), models.SeverityCritical, []string{"auth0", "auth"}, "Auth0", "Auth0 Client Secret"},
		{"auth0-domain", "Auth0 Domain", regexp.MustCompile(`[a-z0-9-]+\.auth0\.com`), models.SeverityLow, []string{"auth0", "auth"}, "Auth0", "Auth0 Domain"},

		// Okta
		{"okta-api-token", "Okta API Token", regexp.MustCompile(`(?i)okta(.{0,20})?api[_-]?token[=\s]+['"]?([A-Za-z0-9\-_]{42})['"]?`), models.SeverityCritical, []string{"okta", "sso"}, "Okta", "Okta API Token"},
		{"okta-client-secret", "Okta Client Secret", regexp.MustCompile(`(?i)okta(.{0,20})?client[_-]?secret[=\s]+['"]?([A-Za-z0-9\-_]{30,})['"]?`), models.SeverityCritical, []string{"okta", "sso"}, "Okta", "Okta Client Secret"},

		// Splunk
		{"splunk-token", "Splunk Token", regexp.MustCompile(`(?i)splunk(.{0,20})?token[=\s]+['"]?([A-Za-z0-9]{32,})['"]?`), models.SeverityHigh, []string{"splunk", "logging"}, "Splunk", "Splunk HTTP Event Collector Token"},

		// Sumo Logic
		{"sumologic-access-id", "Sumo Logic Access ID", regexp.MustCompile(`(?i)sumologic(.{0,20})?access[_-]?id[=\s]+['"]?([A-Za-z0-9]{14})['"]?`), models.SeverityHigh, []string{"sumologic", "logging"}, "SumoLogic", "Sumo Logic Access ID"},
		{"sumologic-access-key", "Sumo Logic Access Key", regexp.MustCompile(`(?i)sumologic(.{0,20})?access[_-]?key[=\s]+['"]?([A-Za-z0-9]{36})['"]?`), models.SeverityHigh, []string{"sumologic", "logging"}, "SumoLogic", "Sumo Logic Access Key"},

		// Elastic
		{"elastic-cloud-id", "Elastic Cloud ID", regexp.MustCompile(`(?i)elastic[_-]?cloud[_-]?id[=\s]+['"]?([A-Za-z0-9]{10,}:[A-Za-z0-9=]{10,})['"]?`), models.SeverityMedium, []string{"elastic", "search"}, "Elastic", "Elastic Cloud ID"},
		{"elastic-api-key", "Elastic API Key", regexp.MustCompile(`(?i)elastic(.{0,20})?api[_-]?key[=\s]+['"]?([A-Za-z0-9\-_]{20,})['"]?`), models.SeverityHigh, []string{"elastic", "search"}, "Elastic", "Elasticsearch API Key"},

		// Cloudwatch
		{"cloudwatch-log-group", "CloudWatch Log Group", regexp.MustCompile(`(?i)cloudwatch(.{0,20})?log[_-]?group[=\s]+['"]?(\/aws[^\s'"]{10,})['"]?`), models.SeverityLow, []string{"aws", "cloudwatch"}, "AWS", "CloudWatch Log Group Name"},
	}
}

func (s *Scanner) ScanPath(path string, customExcludes ...string) ([]models.Finding, error) {
	var findings []models.Finding

	defaultExcludes := []string{
		"testdata",
		"vendor",
		"node_modules",
		".git",
		"tmp",
		"dist",
		"build",
		".github",
	}

	excludes := append(defaultExcludes, customExcludes...)

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			dirName := info.Name()
			for _, exclude := range excludes {
				if dirName == exclude {
					return filepath.SkipDir
				}
			}
			return nil
		}

		fileName := info.Name()
		ext := filepath.Ext(fileName)

		binaryExtensions := []string{".exe", ".so", ".dll", ".dylib", ".bin", ".a", ".o", ".obj"}
		for _, e := range binaryExtensions {
			if ext == e {
				return nil
			}
		}

		if ext == "" && !strings.HasSuffix(fileName, ".go") && !strings.HasSuffix(fileName, ".json") && !strings.HasSuffix(fileName, ".mod") {
			return nil
		}

		skipExtensions := []string{".md", ".txt", ".rst", ".yaml", ".yml", ".json"}
		for _, e := range skipExtensions {
			if ext == e && fileName != "package.json" && fileName != "go.mod" {
				return nil
			}
		}

		ruleFiles := []string{"scanner.go", "risk.go", "engine.go", "validator.go"}
		for _, rf := range ruleFiles {
			if fileName == rf {
				return nil
			}
		}

		if strings.HasSuffix(fileName, "_test.go") {
			return nil
		}

		for _, exclude := range excludes {
			if strings.Contains(filePath, "/"+exclude+"/") || strings.HasSuffix(filePath, "/"+exclude) {
				return nil
			}
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil
		}

		fileFindings := s.scanContent(string(content), filePath)
		findings = append(findings, fileFindings...)

		return nil
	})

	return findings, err
}

func (s *Scanner) ScanContent(content string) []models.Finding {
	return s.scanContent(content, "stdin")
}

func (s *Scanner) scanContent(content, filePath string) []models.Finding {
	var findings []models.Finding
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		for _, rule := range s.rules {
			matches := rule.Pattern.FindAllStringSubmatch(line, -1)
			if len(matches) > 0 {
				for _, match := range matches {
					if len(match) > 1 && match[1] != "" {
						finding := models.Finding{
							ID:        generateID(filePath, lineNum, rule.ID),
							RuleID:    rule.ID,
							RuleName:  rule.Name,
							Severity:  rule.Severity,
							Match:     match[0],
							File:      filePath,
							Line:      lineNum + 1,
							Entropy:   calculateEntropy(match[0]),
							Tags:      rule.Tags,
							Context:   getContext(lines, lineNum),
							Timestamp: time.Now(),
						}
						findings = append(findings, finding)
					}
				}
			}
		}
	}

	return findings
}

func (s *Scanner) ScanWithGitleaks(path string) ([]models.Finding, error) {
	cmd := exec.Command("gitleaks", "detect", "--source", path, "--report-format", "json", "-v")
	output, err := cmd.Output()

	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			return s.ScanPath(path)
		}
		return nil, err
	}

	var gitleaksResults []GitleaksResult
	if err := json.Unmarshal(output, &gitleaksResults); err != nil {
		return s.ScanPath(path)
	}

	var findings []models.Finding
	for _, gl := range gitleaksResults {
		finding := models.Finding{
			ID:        generateID(gl.File, gl.LineNumber, gl.RuleID),
			RuleID:    gl.RuleID,
			RuleName:  gl.RuleID,
			Match:     gl.Match,
			File:      gl.File,
			Line:      gl.LineNumber,
			Commit:    gl.Commit,
			Entropy:   gl.Entropy,
			Tags:      gl.Tags,
			Timestamp: time.Now(),
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

func generateID(file string, line int, rule string) string {
	data := fmt.Sprintf("%s-%d-%s", file, line, rule)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}

	entropy := 0.0
	for _, count := range freq {
		p := count / float64(len(s))
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func getContext(lines []string, lineNum int) string {
	start := lineNum - 2
	if start < 0 {
		start = 0
	}

	end := lineNum + 3
	if end > len(lines) {
		end = len(lines)
	}

	var context []string
	for i := start; i < end; i++ {
		prefix := "  "
		if i == lineNum {
			prefix = "> "
		}
		context = append(context, fmt.Sprintf("%s%d: %s", prefix, i+1, lines[i]))
	}

	return strings.Join(context, "\n")
}

func (s *Scanner) GetRules() []Rule {
	return s.rules
}

func (s *Scanner) GetServiceCount() map[string]int {
	count := make(map[string]int)
	for _, rule := range s.rules {
		count[rule.Service]++
	}
	return count
}