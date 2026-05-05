# SecretHunter

<p align="center">

```
___ ___ ___ ___ ___ _____ _  _ _  _ _  _ _____ ___ ___ 
 / __| __/ __| _ \ __/_   _| || | || | || |_   _| __| _ \
 \__ \ _| (__|   / _|  | | | __ | || | __ | | | | _||   /
 |___/___\___|_|_\___| |_| |_||_|\__/|_||_| |_| |___|_|_\
 
 < SECRETHUNTER::AI_POWERED_SECRET_SCANNER_v1.0 />
 < 175+_PATTERNS::MULTI_AI::REALTIME_VALIDATION />
```

</p>

<p align="center">
  <a href="https://go.dev/">
    <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go" alt="Go Version">
  </a>
  <a href="https://github.com/secrethunter/secrethunter/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  </a>
  <a href="https://github.com/secrethunter/secrethunter/stargazers">
    <img src="https://img.shields.io/github/stars/secrethunter/secrethunter?style=for-the-badge" alt="Stars">
  </a>
</p>

---

## What is SecretHunter?

**SecretHunter** is an AI-powered CLI tool that scans your code repositories for leaked API keys, tokens, and secrets. It uses advanced detection patterns combined with AI-driven false positive analysis to identify real security threats while reducing noise.

### Why Use SecretHunter?

- 🔍 **175+ Detection Patterns** - Covers 60+ cloud services and platforms
- 🤖 **AI False Positive Detection** - Uses LLM to analyze context and determine if findings are real
- ⚡ **Fast Scanning** - Scans repositories in seconds
- 📊 **Risk Reports** - Detailed CVSS-based risk analysis
- 🔐 **Key Validation** - Test if exposed keys are still valid (your own keys only)

---

## Features

### Supported Services

| Category | Services |
|----------|----------|
| **Cloud Providers** | AWS, Google Cloud, Azure, Alibaba, Tencent, Qiniu, DigitalOcean, Cloudflare |
| **AI/ML** | OpenAI, Anthropic, HuggingFace, Replicate, Perplexity |
| **DevOps** | GitHub, GitLab, Bitbucket, Heroku, Docker, Kubernetes |
| **Communication** | Slack, Discord, Telegram, Twilio, SendGrid, Mailgun |
| **Payments** | Stripe, PayPal, Square |
| **Databases** | MongoDB, PostgreSQL, MySQL, Redis |
| **Cryptographic** | RSA/EC/DSA Private Keys, SSH Keys, JWT Tokens |

### Key Capabilities

- **Intelligent Scanning** - Regex-based detection with entropy analysis
- **AI-Powered Analysis** - Uses OpenAI, Anthropic, or Ollama to filter false positives
- **Risk Assessment** - CVSS scoring with compliance recommendations
- **Auto Cleanup** - Automatically removes cloned repositories after scanning
- **Interactive CLI** - Metasploit-style interface for easy use

---

## Installation

### Prerequisites

- **Go 1.22+** (or use pre-built binary)
- **Git** (for scanning GitHub repositories)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/secrethunter.git
cd secrethunter

# Run the binary
./secrethunter
```

### Build from Source

```bash
# If you have Go installed
go build -o secrethunter .

# Run
./secrethunter
```

---

## Usage

### Starting the CLI

```bash
./secrethunter
```

You'll see the banner and help:

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ████████╗██║    ██╗ ██████╗ 
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║    ██║██╔═══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝   ██║   ██║ █╗ ██║██║   ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗   ██║   ██║███╗██║██║   ██║
╚██████╗   ██║   ██║  ██║███████╗██║  ██║   ██║   ╚███╔███╔╝╚██████╔╝
 ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ 

            [ AI POWERED :: SECRET SCANNER v1.0 ]

SecretHunter> help
```

---

### Configuration

#### Set OpenAI API Key
```
set openai sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

#### Set Anthropic API Key
```
set anthropic sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

#### Set Ollama (Local AI)
```
set ollama llama3
```

---

### Scanning

#### Scan Local Directory
```
scan local /path/to/your/project
scan local ./myproject
```

#### Scan GitHub Repository
```
scan github https://github.com/username/repo
```

#### Scan Raw Content
```
scan content api_key = "sk-1234567890abcdef"
```

---

### Analysis & Results

#### View All Findings
```
results
```

#### Table Format
```
results --table
```

#### JSON Format
```
results --json
```

#### Summary Statistics
```
results --summary
```

#### Detailed Report
```
report
```

---

### AI Analysis

**Note:** Requires OpenAI or Anthropic API key

```
set openai YOUR_API_KEY
analyze all
```

This will:
- Analyze each finding
- Determine if it's a REAL secret or FALSE POSITIVE
- Provide confidence score and reasoning
- Suggest recommendations

---

### Validation

⚠️ **WARNING:** Only validate keys that YOU own!

```
validate 1
validate all
```

---

### Export

```
export json results.json
export txt results.txt
```

---

### Other Commands

```
status         - Show current configuration
rules          - Show available detection rules
clear          - Clear results
exit           - Exit
```

---

## Demo

### Example Session

```bash
SecretHunter> scan github https://github.com/user/repo
Scanning...
Cloning into '/tmp/secrethunter-repo'...
  [Cleaned up cloned repository]

Scan complete!
Found: 5 potential secrets
Time: 2.34s

SecretHunter> results --table
Num  Severity   Rule                                     File                          
------------------------------------------------------------------------------------------
1    CRITICAL   AWS Access Key ID                        /repo/config.py:12           
2    HIGH       OpenAI API Key                           /repo/app.py:45             
3    MEDIUM     Generic API Key                          /repo/test.py:8              
4    MEDIUM     JSON Secret                              /repo/config.json:3         
5    LOW        Environment Variable                     /repo/.env:1                

SecretHunter> report
═══════════════════════════════════════════════════════════════════
              SECRET HUNTER - RISK REPORT
═══════════════════════════════════════════════════════════════════

TARGET: GitHub Repo
TOTAL FINDINGS: 5
OVERALL RISK: HIGH (CVSS: 7.8)

═══════════════════════════════════════════════════════════════════
                      FINDINGS DETAIL
═══════════════════════════════════════════════════════════════════

[1] AWS Access Key ID
    Severity: critical | CVSS: 9.1
    Impact: Full access to AWS resources, data breach
    Recommendation: Rotate immediately. Check CloudTrail.
    Compliance: PCI-DSS, SOC2, GDPR

═══════════════════════════════════════════════════════════════════
                    REMEDIATION STEPS
═══════════════════════════════════════════════════════════════════

1. IMMEDIATE ACTIONS:
   - Rotate all exposed credentials
   - Review access logs

2. PREVENTION:
   - Use secrets management tools
   - Add pre-commit hooks
   - Add sensitive files to .gitignore

═══════════════════════════════════════════════════════════════════
```

---

## Detection Rules

SecretHunter includes **175+ detection rules** covering:

### Cloud & Infrastructure (50+ rules)
- AWS Access Keys, Secret Keys, MWS Tokens
- Google API Keys, OAuth Tokens, Firebase Keys
- Azure Connection Strings, Client Secrets
- Qiniu, Alibaba, Tencent, DigitalOcean

### AI/ML Services (10+ rules)
- OpenAI API Keys
- Anthropic Keys
- HuggingFace Tokens

### DevOps & Version Control (15+ rules)
- GitHub, GitLab, Bitbucket Tokens
- Heroku API Keys

### Communication (20+ rules)
- Slack, Discord, Telegram, Twilio
- SendGrid, Mailgun

### Payments (10+ rules)
- Stripe, PayPal, Square

### Cryptographic (15+ rules)
- RSA/EC/DSA Private Keys
- JWT Tokens
- SSH Keys

---

## Legal Disclaimer

⚠️ **Important:** This tool is for:

1. **Scanning your own repositories** - Finding your own exposed keys
2. **Authorized security testing** - With permission from the repository owner

**Do NOT** use this tool to:
- Scan repositories you don't own without permission
- Validate exposed keys that don't belong to you
- Harvest credentials for malicious purposes

Unauthorized access to computer systems is illegal. Use responsibly.

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- Built with Go
- Detection patterns inspired by Gitleaks and TruffleHog
- AI analysis powered by OpenAI, Anthropic, and Ollama

---

<p align="center">
Made with ❤️ by SecretHunter
</p>