# Makinde Insecure - Security Scanner Test Repository

⚠️ **WARNING: This repository contains intentionally vulnerable code for testing purposes only. DO NOT use any code from this repository in production environments.**

## 🎯 Purpose

This repository is a comprehensive test suite for the [appsec-static-scanner](https://github.com/ayoolamakinde/appsec-static-scanner) reusable workflows. It contains intentionally insecure code across multiple languages, frameworks, and infrastructure configurations to validate security scanning capabilities.

## 🧪 What's Inside

### Infrastructure as Code (IAC)
- **Terraform** - Insecure AWS/Azure/GCP configurations
- **Kubernetes** - Vulnerable pod/deployment manifests
- **Docker** - Insecure Dockerfiles with exposed secrets and misconfigurations
- **CloudFormation** - AWS templates with security issues
- **Bicep** - Azure resource definitions with vulnerabilities

### Application Code (SAST)
- **Python** - SQL injection, command injection, insecure deserialization
- **JavaScript/TypeScript** - XSS, prototype pollution, path traversal
- **Go** - SQL injection, hardcoded credentials, insecure crypto
- **Java** - Injection flaws, insecure dependencies, weak crypto

### Dependencies (SCA)
- Outdated packages with known CVEs
- Vulnerable dependency chains
- Packages with critical security advisories

### Secrets
- Hardcoded API keys (fake/revoked)
- AWS credentials in code
- Private keys and certificates
- Database connection strings
- OAuth tokens

## 🔍 Security Scans

This repository uses all four security scanning workflows from `appsec-static-scanner`:

| Scan Type | Tool | Status |
|-----------|------|--------|
| **SCA** | Trivy | ✅ Scans dependencies for CVEs |
| **SAST** | Semgrep | ✅ Analyzes code for vulnerabilities |
| **IAC** | Checkov | ✅ Checks infrastructure configs |
| **Secrets** | TruffleHog | ✅ Detects exposed credentials |

All scan results are sent to Slack for visibility.

## 📋 Test Coverage

### IAC Vulnerabilities
- ✅ Unencrypted S3 buckets
- ✅ Publicly accessible databases
- ✅ Overly permissive IAM roles
- ✅ Missing network security groups
- ✅ Containers running as root
- ✅ Exposed Kubernetes dashboards
- ✅ Insecure Docker base images

### Application Vulnerabilities
- ✅ SQL injection (Python, Java, Go)
- ✅ Command injection (Python, Node.js)
- ✅ Cross-site scripting (JavaScript)
- ✅ Path traversal (Python, Java)
- ✅ Insecure deserialization (Python, Java)
- ✅ Hardcoded secrets (all languages)
- ✅ Weak cryptography (Python, Go)
- ✅ SSRF (Server-Side Request Forgery)

### Dependency Vulnerabilities
- ✅ Packages with critical CVEs
- ✅ Outdated frameworks (Django 1.x, Spring Boot 2.0.x)
- ✅ Vulnerable npm packages (lodash 4.17.15, etc.)
- ✅ Known malicious packages

## 🚀 How to Use

### Running Scans

Scans run automatically on:
- Every push to `main` or `develop`
- Every pull request
- Manual workflow dispatch

### Viewing Results

- **GitHub Actions**: Check the Actions tab for workflow runs
- **Slack**: Notifications sent to configured channel
- **Security Tab**: SARIF uploads visible in GitHub Security

### Manual Testing

```bash
# Clone the repository
git clone git@github.com:ayoolamakinde/makinde-insecure.git
cd makinde-insecure

# Trigger scans manually via GitHub UI:
# Actions → Security Scans → Run workflow
```

## 🛡️ Expected Findings

This repository **should** trigger numerous security findings:

- **SCA**: 50+ vulnerable dependencies
- **SAST**: 100+ code vulnerabilities across all severity levels
- **IAC**: 75+ infrastructure misconfigurations
- **Secrets**: 20+ exposed credentials

If scans don't detect these issues, the scanner configuration may need adjustment.

## ⚙️ Scanner Configuration

Scan configuration in `.github/workflows/security-scans.yml`:
- **Severity**: All levels (CRITICAL, HIGH, MEDIUM, LOW)
- **Fail on**: HIGH or above (workflow will fail)
- **Notifications**: Slack webhook for all findings
- **PR Comments**: Detailed findings posted on pull requests
- **GitHub Issues**: Auto-created for CRITICAL findings

## 📁 Repository Structure

```
makinde-insecure/
├── .github/
│   └── workflows/
│       └── security-scans.yml      # Main security workflow
├── terraform/                       # Insecure Terraform configs
│   ├── aws/                        # AWS resources
│   ├── azure/                      # Azure resources
│   └── gcp/                        # GCP resources
├── kubernetes/                      # Vulnerable K8s manifests
│   ├── deployments/
│   └── services/
├── docker/                          # Insecure Dockerfiles
├── python/                          # Vulnerable Python code
│   ├── requirements.txt            # Outdated dependencies
│   └── vulnerable_app.py
├── javascript/                      # Vulnerable Node.js code
│   ├── package.json                # Vulnerable npm packages
│   └── vulnerable_app.js
├── go/                             # Vulnerable Go code
│   ├── go.mod
│   └── vulnerable_app.go
├── java/                           # Vulnerable Java code
│   ├── pom.xml                     # Vulnerable Maven deps
│   └── VulnerableApp.java
└── README.md
```

## 🔒 Security Notes

### Safe to Use
- All secrets are **fake** or **revoked**
- No real credentials or production data
- Isolated test environment only

### Not Safe to Use
- ❌ Do not deploy this code anywhere
- ❌ Do not copy code patterns into real applications
- ❌ Do not expose this repository publicly without understanding risks

## 🤝 Contributing

Want to add more test cases?

1. Add vulnerable code examples
2. Ensure they trigger appropriate scanner detections
3. Document expected findings in this README
4. Submit a pull request

## 📚 Related Projects

- [appsec-static-scanner](https://github.com/ayoolamakinde/appsec-static-scanner) - The security scanning workflows being tested

## 📄 License

MIT License - Use at your own risk for testing purposes only.

---

**Remember**: This code is intentionally insecure. Never use it in production! 🚨
