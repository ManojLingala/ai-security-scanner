# AI Security Scanner CLI - Usage Guide

The AI Security Scanner CLI (`aiscan`) is a command-line tool for AI-powered security vulnerability scanning and compliance checking.

## Installation

### Build from Source
```bash
cd src/AISecurityScanner.CLI
dotnet build
dotnet run -- [command] [options]
```

### Install as Global Tool (Coming Soon)
```bash
dotnet tool install -g AISecurityScanner.CLI
aiscan --help
```

## Quick Start

1. **Authenticate with Claude Code token**
   ```bash
   aiscan auth login
   ```

2. **Scan a single file**
   ```bash
   aiscan scan file MyController.cs
   ```

3. **Scan entire project**
   ```bash
   aiscan scan project
   ```

4. **Run compliance scan**
   ```bash
   aiscan compliance scan --framework pci-dss
   ```

## Commands Overview

### Authentication Commands

#### `aiscan auth login`
Authenticate with Claude Code token. The CLI will:
1. Check for existing Claude Code CLI authentication
2. Request user consent for token access
3. Allow manual token entry if needed
4. Store credentials securely in `~/.aiscan/config.json`

**Example:**
```bash
$ aiscan auth login
🔐 AI Security Scanner Authentication
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Found existing Claude Code authentication!

🔒 PERMISSION REQUEST
━━━━━━━━━━━━━━━━━━━━━━
The AI Security Scanner would like to:
  • Access your Claude API token for security scanning
  • Analyze code files for security vulnerabilities
  • Generate compliance reports
  • Store scan results locally

Do you consent to these permissions? (y/n): y

✅ Authentication successful!
🎉 You can now use AI Security Scanner CLI commands
```

#### `aiscan auth status`
Check current authentication status.

**Example:**
```bash
$ aiscan auth status
🔐 Authentication Status
━━━━━━━━━━━━━━━━━━━━━━━
Status: ✅ Authenticated
Token: sk-a...3kL
Last Login: 2025-01-21 14:30:15
Consent Given: True
```

#### `aiscan auth logout`
Clear stored credentials.

### Security Scanning Commands

#### `aiscan scan file <path>`
Scan a single source file for security vulnerabilities.

**Options:**
- `--format table|json|csv` - Output format (default: table)

**Example:**
```bash
$ aiscan scan file Controllers/UserController.cs --format table
🔍 Scanning file: Controllers/UserController.cs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Scan completed in 2.34s

🚨 High Severity (2 issues):

 ------------------------------------------------------------------------------- 
 | Line | Type              | Description                      | Confidence | CWE |
 ------------------------------------------------------------------------------- 
 | 42   | SQL Injection     | Unsanitized user input in query | 9.2        | 89  |
 ------------------------------------------------------------------------------- 
 | 67   | XSS               | Unencoded output to response     | 8.7        | 79  |
 ------------------------------------------------------------------------------- 
```

#### `aiscan scan directory <path>`
Scan all files in a directory.

**Options:**
- `--format table|json|csv` - Output format (default: table)
- `--recursive` - Scan subdirectories (default: true)

**Example:**
```bash
$ aiscan scan directory ./src --format table
🔍 Scanning directory: ./src
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Found 15 files to scan

  📄 Controllers/UserController.cs... ✅ 3 issues
  📄 Models/UserModel.cs... ✅ 0 issues
  📄 Services/AuthService.cs... ✅ 1 issues
  ...

📊 Scan Summary: 15/15 files scanned
🚨 Found 8 total vulnerabilities
```

#### `aiscan scan project`
Scan the current project/repository.

**Options:**
- `--format table|json|csv` - Output format (default: table)

**Example:**
```bash
$ aiscan scan project
🔍 Scanning current project: /Users/dev/MyProject
📋 Detected project files: MyProject.csproj
📁 Found 25 files to scan
...
```

### Compliance Scanning Commands

#### `aiscan compliance list`
List all supported compliance frameworks.

**Example:**
```bash
$ aiscan compliance list
🛡️ Supported Compliance Frameworks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 ----------------------------------------------------------------------------------------------- 
 | Code    | Framework           | Description                                         | Rules |
 ----------------------------------------------------------------------------------------------- 
 | pci-dss | PCI DSS v4.0        | Payment Card Industry Data Security Standard        | 22    |
 | hipaa   | HIPAA Security Rule | Health Insurance Portability and Accountability Act | 18    |
 | sox     | SOX                 | Sarbanes-Oxley Act Financial Controls               | 15    |
 | gdpr    | GDPR                | General Data Protection Regulation                  | 21    |
 ----------------------------------------------------------------------------------------------- 

💡 Usage: aiscan compliance scan --framework <code>
```

#### `aiscan compliance scan --framework <framework>`
Run compliance scan for specific framework.

**Options:**
- `--framework pci-dss|hipaa|sox|gdpr` - Compliance framework (required)
- `--path <directory>` - Path to scan (default: current directory)
- `--format table|json|csv` - Output format (default: table)

**Example:**
```bash
$ aiscan compliance scan --framework pci-dss --path ./src
🛡️ Running PCI DSS v4.0 compliance scan
📁 Directory: ./src
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📄 Found 25 files to scan
✅ Compliance scan completed in 5.67s
📋 22 rules evaluated

🎯 Overall Compliance Score: 76.3%

🚨 Compliance Violations:

🔴 Critical (3 violations):
 ----------------------------------------------------------------------------------------- 
 | Rule ID  | Title                    | File            | Line | Guidance               |
 ----------------------------------------------------------------------------------------- 
 | PCI-3.2  | Credit Card Pattern     | config.json     | 12   | Remove CC from config  |
 | PCI-6.1  | SQL Injection           | UserService.cs  | 45   | Use parameterized...   |
 ----------------------------------------------------------------------------------------- 

📊 Category Scores:
 --------------------------------------------------------- 
 | Category           | Score  | Status     |
 --------------------------------------------------------- 
 | cardholder data    | 45.2%  | ❌ Fail    |
 | network security   | 89.1%  | ✅ Pass    |
 | access control     | 78.5%  | ⚠️ Warning |
 --------------------------------------------------------- 

🔧 High Priority Actions:
  • Immediately encrypt all stored cardholder data using AES-256
  • Fix SQL injection vulnerabilities using parameterized queries
  • Remove hardcoded secrets and implement secure configuration management
```

### Configuration Commands

#### `aiscan config list`
List all configuration settings.

**Example:**
```bash
$ aiscan config list
⚙️ Configuration Settings
━━━━━━━━━━━━━━━━━━━━━━━━
Output Format: table
Scan Timeout: 300s
Max Concurrent Scans: 3
Enabled Frameworks: pci-dss, hipaa
```

#### `aiscan config get <key>`
Get a configuration value.

**Example:**
```bash
$ aiscan config get output_format
table
```

#### `aiscan config set <key> <value>`
Set a configuration value.

**Available Settings:**
- `output_format` - Default output format (table/json/csv)
- `scan_timeout` - Scan timeout in seconds
- `max_concurrent_scans` - Maximum concurrent scans

**Example:**
```bash
$ aiscan config set output_format json
✅ Set output_format = json
```

### Utility Commands

#### `aiscan version`
Show version information.

**Example:**
```bash
$ aiscan version
AI Security Scanner CLI v1.0.0
AI-powered security vulnerability scanning and compliance checking

🤖 Powered by Claude AI
🛡️ Supporting PCI DSS, HIPAA, SOX, and GDPR compliance frameworks
```

#### `aiscan --help`
Show help and usage information.

## Output Formats

### Table Format (Default)
Human-readable table output with colors and formatting.

### JSON Format
Machine-readable JSON for integration with other tools.

**Example:**
```bash
$ aiscan scan file app.js --format json
{
  "vulnerabilities": [
    {
      "id": "guid",
      "type": "XSS",
      "severity": "High",
      "confidence": 8.7,
      "description": "Potential XSS vulnerability",
      "lineNumber": 42,
      "code": "document.write(userInput);",
      "recommendation": "Use safe DOM manipulation methods"
    }
  ]
}
```

### CSV Format
Comma-separated values for spreadsheet import.

**Example:**
```bash
$ aiscan scan file app.js --format csv
Line,Type,Severity,Description,Confidence,CWE,Recommendation
42,XSS,High,"Potential XSS vulnerability",8.7,79,"Use safe DOM manipulation methods"
```

## Configuration File

The CLI stores configuration in `~/.aiscan/config.json`:

```json
{
  "claude_token": "sk-ant-...",
  "output_format": "table",
  "scan_timeout": 300,
  "max_concurrent_scans": 3,
  "compliance_frameworks": ["pci-dss", "hipaa"],
  "last_login": "2025-01-21T14:30:15.123Z",
  "user_consent_given": true
}
```

## Supported File Types

The scanner supports these file extensions:
- **C#**: `.cs`
- **JavaScript/TypeScript**: `.js`, `.ts`
- **Python**: `.py`
- **Java**: `.java`
- **C/C++**: `.c`, `.cpp`, `.cxx`, `.cc`
- **PHP**: `.php`
- **Configuration**: `.config`, `.json`, `.xml`, `.yml`, `.yaml`
- **Database**: `.sql`
- **Logs**: `.txt`, `.log`

## Error Handling

### Authentication Errors
```bash
❌ You are not authenticated.
Run 'aiscan auth login' to authenticate first.
```

### File Not Found
```bash
❌ File not found: /path/to/nonexistent.cs
```

### Invalid Framework
```bash
❌ Unsupported framework: invalid-framework
Run 'aiscan compliance list' to see supported frameworks.
```

## Integration Examples

### CI/CD Pipeline
```bash
#!/bin/bash
# Run security scan and fail if critical vulnerabilities found
aiscan scan project --format json > scan-results.json

# Check for critical/high severity issues
CRITICAL_COUNT=$(cat scan-results.json | jq '.vulnerabilities[] | select(.severity == "Critical" or .severity == "High") | length')

if [ "$CRITICAL_COUNT" -gt 0 ]; then
  echo "❌ Found $CRITICAL_COUNT critical/high severity vulnerabilities"
  exit 1
fi

echo "✅ Security scan passed"
```

### Pre-commit Hook
```bash
#!/bin/bash
# Scan staged files before commit
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(cs|js|ts|py|java)$')

for FILE in $STAGED_FILES; do
  aiscan scan file "$FILE" --format json | jq -e '.vulnerabilities | length == 0' > /dev/null
  if [ $? -ne 0 ]; then
    echo "❌ Security vulnerabilities found in $FILE"
    exit 1
  fi
done
```

## Troubleshooting

### Common Issues

**Authentication Fails**
- Ensure Claude Code CLI is installed and authenticated
- Check if API token is valid
- Verify network connectivity

**No Files Found**
- Check that the directory contains supported file types
- Verify file extensions are recognized
- Ensure proper file permissions

**Compliance Scan Errors**
- Verify the framework code is correct (`pci-dss`, `hipaa`, `sox`, `gdpr`)
- Check that files are accessible
- Ensure sufficient disk space for temporary files

### Getting Help

- Use `aiscan --help` for general help
- Use `aiscan [command] --help` for command-specific help
- Check the configuration with `aiscan config list`
- Verify authentication with `aiscan auth status`

## Roadmap

### Upcoming Features
- [ ] GitHub/GitLab integration
- [ ] Custom rule definitions
- [ ] Report export (PDF, HTML)
- [ ] Webhook notifications
- [ ] Plugin system for custom scanners
- [ ] Docker container support
- [ ] VS Code extension integration

---

**Version**: 1.0.0  
**Last Updated**: January 21, 2025  
**Powered by**: Claude AI & .NET 8