# AI Security Scanner CLI

🤖 **Intelligent vulnerability detection powered by Claude AI**

The AI Security Scanner CLI is a powerful command-line tool that leverages artificial intelligence to detect security vulnerabilities, analyze code quality, and ensure compliance with industry standards. Built with C# and integrated with Claude AI, it provides comprehensive security scanning capabilities for modern applications.

## 🚀 Quick Start

### Installation
```bash
# Install as global tool
dotnet tool install --global aiscan

# Or build from source
git clone <repository>
cd AISecurityScanner/src/AISecurityScanner.CLI
dotnet build
dotnet run
```

### First Run
```bash
# Launch interactive mode
aiscan

# Or authenticate first
aiscan auth login
```

## 📋 Command Reference

### Basic Usage
```bash
# Scan current directory
aiscan scan @.

# Scan specific file
aiscan scan UserController.cs

# Interactive configuration
aiscan --interactive
```

### Enhanced Commands (Slash System)
```bash
# Quick directory scan
aiscan /scan @src/

# Deep analysis with compliance checking
aiscan /scan @. --deep --compliance=PCI-DSS,HIPAA

# Performance optimized scan
aiscan /scan @. --performance=optimization

# Watch mode for development
aiscan /scan @src/ --watch
```

### Authentication
```bash
aiscan auth login      # Authenticate with Claude AI
aiscan auth status     # Check authentication status
aiscan auth logout     # Clear stored credentials
```

### Configuration Management
```bash
aiscan config list                    # Show all settings
aiscan config set OutputFormat json  # Set specific setting

# Profile management
aiscan profile list                   # List all profiles
aiscan profile apply comprehensive    # Apply profile
aiscan profile create my-settings     # Create new profile
```

### Compliance Scanning
```bash
aiscan compliance list                           # List frameworks
aiscan compliance scan --framework pci-dss      # Specific framework
aiscan /scan @. --compliance=PCI-DSS,HIPAA      # Multiple frameworks
```

### Quick Actions
```bash
aiscan quick scan     # Quick scan current directory
aiscan quick owasp    # OWASP Top 10 check
```

## 🎯 Advanced Features

### Wave Orchestration
Multi-stage scanning that automatically adjusts based on project complexity:

```bash
aiscan /scan @large-project/ --deep
```

**Output:**
```
🌊 Wave Orchestration Started (Complexity: 0.82)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔄 Quick Scan: Fast vulnerability detection... ✅ (2.1s)
   • Found 5 potential issues
🔄 Deep Analysis: Comprehensive code analysis... ✅ (8.3s)
   • Completed AI-powered deep analysis
🔄 Compliance Check: Checking PCI-DSS, HIPAA... ✅ (3.5s)
   • Found 2 compliance issues

📊 Wave Summary: 3/3 waves completed successfully
⏱️  Total duration: 13.9s
```

### Performance Profiles
```bash
--performance=optimization   # Fast parallel scanning (8 workers)
--performance=standard      # Balanced scanning (4 workers)
--performance=complex       # Deep sequential analysis (2 workers)
```

### Scan Estimation
```bash
aiscan /scan @large-project/ --estimate
```

**Output:**
```
📊 Scan Estimation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Files to scan: 1,234
💾 Total size: 45.2 MB
🧮 Complexity score: 0.82
⏱️  Estimated time: 5m 30s
🧠 Estimated memory: ~350MB

Continue with scan? (y/n):
```

### Watch Mode
```bash
aiscan /scan @src/ --watch
```

**Output:**
```
👁️  Watch mode enabled - monitoring for changes...
Press Ctrl+C to stop

🔄 Detected changes in 2 file(s), rescanning...
```

### Output Formats
```bash
--format=table    # Console table (default)
--format=json     # JSON for CI/CD integration
--format=csv      # CSV for Excel import
--format=sarif    # SARIF for GitHub/Azure DevOps
--format=html     # HTML report for web viewing
```

## 🏗️ Technical Architecture

### Command Flow
```
User Input → CLI Parser → Command Handler → Services → AI Providers → Results → CLI Output
```

### API Integration
The CLI integrates with multiple backend services:

1. **Claude AI Provider** (`ClaudeProvider`)
   - **Endpoint**: Claude API via HTTP client
   - **Authentication**: Bearer token from config
   - **Purpose**: AI-powered vulnerability analysis

2. **Compliance Services** (`ComplianceService`)
   - **Frameworks**: PCI-DSS, HIPAA, SOX, GDPR, OWASP
   - **Implementation**: Pattern-based rule matching
   - **Output**: Compliance violations and recommendations

3. **Configuration Service** (`ConfigService`)
   - **Storage**: `~/.aiscan/config.json`
   - **Profiles**: `~/.aiscan/profiles/*.json`
   - **Settings**: User preferences and authentication

### Service Architecture
```csharp
// Dependency Injection Setup
services.AddScoped<ConfigService>();
services.AddScoped<AuthService>();
services.AddScoped<ScanService>();
services.AddScoped<ComplianceCliService>();
services.AddScoped<InteractiveModeService>();
services.AddScoped<ConfigurationProfileService>();

// AI Provider Integration
services.AddScoped<ClaudeProvider>();
services.AddScoped<IAIProvider>(provider => 
    provider.GetRequiredService<ClaudeProvider>());
```

### Command Architecture
Each command inherits from `BaseCommand` and includes:
- **Metadata**: Category, purpose, performance profile
- **Wave Support**: Multi-stage execution capability
- **Aliases**: Multiple invocation methods
- **Examples**: Usage documentation

```csharp
public class ScanCommandV2 : BaseCommand
{
    public override CommandMetadata Metadata => new()
    {
        Command = "/scan",
        Category = "Security Analysis",
        WaveEnabled = true,
        PerformanceProfile = PerformanceProfile.Standard
    };
}
```

## 🔌 API Endpoints

### Claude AI Integration
```csharp
// Authentication
Headers: { Authorization: "Bearer <claude-token>" }

// Analysis Request
POST /api/analyze
{
    "code": "source code content",
    "language": "C#",
    "context": {
        "organizationId": "guid",
        "includeAIDetection": true,
        "includePackageValidation": false
    }
}

// Response
{
    "isSuccess": true,
    "detectedVulnerabilities": [...],
    "confidenceScore": 0.95,
    "responseTime": "00:00:02.1",
    "providerName": "Claude"
}
```

### Configuration Storage
```json
// ~/.aiscan/config.json
{
    "claudeToken": "encrypted-token",
    "outputFormat": "table",
    "scanTimeoutSeconds": 120,
    "maxConcurrentScans": 4,
    "enabledComplianceFrameworks": ["OWASP", "PCI-DSS"],
    "userConsent": true,
    "lastUsed": "2025-01-23T20:30:00Z"
}
```

## 🚢 Deployment

### Local Development
```bash
# Clone repository
git clone <repository-url>
cd AISecurityScanner

# Install dependencies
dotnet restore

# Build solution
dotnet build

# Run CLI
cd src/AISecurityScanner.CLI
dotnet run -- --help
```

### Global Tool Installation
```bash
# Pack as tool
dotnet pack src/AISecurityScanner.CLI/AISecurityScanner.CLI.csproj

# Install globally
dotnet tool install --global --add-source ./nupkg aiscan

# Use anywhere
aiscan --help
```

### Docker Deployment
```dockerfile
FROM mcr.microsoft.com/dotnet/runtime:8.0
COPY publish/ app/
WORKDIR /app
ENTRYPOINT ["dotnet", "aiscan.dll"]
```

```bash
# Build container
docker build -t aiscan .

# Run with volume mount
docker run -v ~/.aiscan:/root/.aiscan aiscan scan @/code
```

### CI/CD Integration
```yaml
# GitHub Actions
- name: Security Scan
  run: |
    dotnet tool install --global aiscan
    aiscan auth login --token ${{ secrets.CLAUDE_TOKEN }}
    aiscan /scan @. --format=sarif --output=security-results.sarif
    
- name: Upload Results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: security-results.sarif
```

```yaml
# Azure DevOps
- task: DotNetCoreCLI@2
  displayName: 'Install Security Scanner'
  inputs:
    command: 'custom'
    custom: 'tool'
    arguments: 'install --global aiscan'

- task: PowerShell@2
  displayName: 'Run Security Scan'
  inputs:
    script: |
      aiscan auth login --token $(CLAUDE_TOKEN)
      aiscan /scan @. --format=sarif --performance=optimization
```

## 💼 Configuration Profiles

### Built-in Profiles

#### Minimal
```json
{
    "name": "minimal",
    "description": "Quick security checks only",
    "settings": {
        "scanTimeoutSeconds": 30,
        "maxConcurrentScans": 8,
        "enabledComplianceFrameworks": []
    }
}
```

#### Standard
```json
{
    "name": "standard", 
    "description": "Balanced security scanning",
    "settings": {
        "scanTimeoutSeconds": 120,
        "maxConcurrentScans": 4,
        "enabledComplianceFrameworks": ["OWASP"]
    }
}
```

#### Comprehensive
```json
{
    "name": "comprehensive",
    "description": "Full compliance audit",
    "settings": {
        "scanTimeoutSeconds": 300,
        "maxConcurrentScans": 2,
        "enabledComplianceFrameworks": ["PCI-DSS", "HIPAA", "SOX", "GDPR", "OWASP"]
    }
}
```

#### CI/CD
```json
{
    "name": "ci-cd",
    "description": "Optimized for pipelines",
    "settings": {
        "outputFormat": "sarif",
        "scanTimeoutSeconds": 60,
        "maxConcurrentScans": 8,
        "enabledComplianceFrameworks": ["OWASP"]
    }
}
```

### Custom Profiles
```bash
# Create from current settings
aiscan profile create production --description="Production security settings"

# Apply custom profile
aiscan profile apply production

# List all profiles
aiscan profile list
```

## 🔒 Security & Compliance

### Supported Frameworks
- **PCI DSS**: Payment card industry standards
- **HIPAA**: Healthcare data protection
- **SOX**: Financial reporting compliance
- **GDPR**: European data privacy
- **OWASP**: Web application security

### Authentication & Privacy
- **Token Storage**: Encrypted locally in `~/.aiscan/config.json`
- **API Communication**: HTTPS with bearer token authentication
- **Data Handling**: Code is sent to Claude AI for analysis
- **User Consent**: Explicit consent required before API calls
- **No Persistence**: CLI mode doesn't store scan results

### Compliance Checking Process
```csharp
public async Task<ComplianceScanResult> ScanAsync(ComplianceScanContext context)
{
    var violations = new List<ComplianceViolation>();
    
    foreach (var file in context.Files)
    {
        var content = await file.ReadContentAsync();
        var lines = content.Split('\n');
        
        foreach (var rule in GetApplicableRules(file.Extension))
        {
            // Pattern matching for compliance violations
            if (rule.IsRegex ? Regex.IsMatch(line, rule.Pattern) 
                            : line.Contains(rule.Pattern))
            {
                violations.Add(CreateViolation(rule, file, lineIndex, line));
            }
        }
    }
    
    return new ComplianceScanResult
    {
        Framework = Framework,
        Violations = violations,
        OverallScore = CalculateComplianceScore(violations),
        Recommendations = GenerateRecommendations(violations)
    };
}
```

## 🎨 Interactive Mode

### Main Menu
```
🤖 AI Security Scanner

What would you like to do?
> 🔍 Quick Scan (current directory)
  📋 Configure & Run Scan  
  🏃 Use Scan Preset
  🔐 Manage Authentication
  ⚙️  Configure Settings
  👤 Manage Profiles
  📊 View Recent Results
  ❓ Help & Documentation
  🚪 Exit
```

### Scan Configuration
- **Visual Selection**: File/directory picker
- **Depth Options**: Quick, Standard, Deep
- **Compliance**: Multi-select frameworks
- **Output Format**: Table, JSON, CSV, SARIF, HTML
- **Progress Indicators**: Real-time scan progress

### Result Display
- **Severity Grouping**: Critical, High, Medium, Low
- **Interactive Navigation**: Drill down into vulnerabilities
- **Recommendation Engine**: Actionable fix suggestions
- **Export Options**: Multiple output formats

## 🐛 Troubleshooting

### Common Issues

#### Authentication Problems
```bash
# Check status
aiscan auth status

# Re-authenticate
aiscan auth logout
aiscan auth login
```

#### Performance Issues
```bash
# Use faster profile
aiscan /scan @. --performance=optimization

# Reduce scan scope
aiscan /scan @src/ --depth=quick
```

#### Memory Problems
```bash
# Scan smaller batches
aiscan /scan @src/controllers/
aiscan /scan @src/services/

# Use estimation first
aiscan /scan @. --estimate
```

### Debug Mode
```bash
# Enable verbose logging
aiscan /scan @. --verbose

# Quiet mode for scripts
aiscan /scan @. --quiet --format=json
```

### Log Files
- **Location**: `~/.aiscan/logs/`
- **Rotation**: Daily log files
- **Content**: Command execution, API calls, errors

## 📊 Performance Benchmarks

### Scan Times (approx.)
| Project Size | Files | Quick | Standard | Deep |
|-------------|-------|-------|----------|------|
| Small | <50 | 5s | 15s | 45s |
| Medium | 50-200 | 15s | 60s | 3m |
| Large | 200-1000 | 45s | 5m | 15m |
| Enterprise | >1000 | 2m | 15m | 45m |

### Memory Usage
| Profile | Base | Per File | Max |
|---------|------|----------|-----|
| Optimization | 50MB | 1MB | 500MB |
| Standard | 75MB | 2MB | 1GB |
| Complex | 100MB | 5MB | 2GB |

### Parallel Processing
- **Optimization**: 8 concurrent workers
- **Standard**: 4 concurrent workers  
- **Complex**: 2 concurrent workers (thorough analysis)

## 🤝 Contributing

### Development Setup
```bash
git clone <repository>
cd AISecurityScanner
dotnet restore
dotnet build
```

### Testing
```bash
# Run unit tests
dotnet test

# Manual testing
cd src/AISecurityScanner.CLI
dotnet run -- /scan test-sample.cs
```

### Adding New Commands
1. Inherit from `BaseCommand`
2. Implement `CommandMetadata`
3. Register in `ConfigureServices()`
4. Add to `ConfigureRootCommand()`

### Code Style
- Follow C# naming conventions
- Use async/await for I/O operations
- Include XML documentation
- Add appropriate error handling

## 📈 Roadmap

### Current Version (v1.0)
- ✅ Basic vulnerability scanning
- ✅ Compliance framework support
- ✅ Interactive mode
- ✅ Configuration profiles
- ✅ Wave orchestration

### Upcoming Features (v1.1)
- 🔄 Result caching
- 🔄 Plugin system
- 🔄 Batch processing
- 🔄 Remote scanning
- 🔄 AI learning feedback

### Future Enhancements (v2.0)
- 📋 Historical trend analysis
- 📋 Team collaboration features
- 📋 Integration marketplace
- 📋 Custom rule engine
- 📋 Advanced reporting

## 📞 Support

### Getting Help
- **Documentation**: This README
- **Issues**: GitHub Issues
- **Community**: Discord/Slack channel
- **Email**: security@aisecurityscanner.com

### Feature Requests
Submit feature requests through GitHub Issues with:
- Clear description
- Use case explanation
- Expected behavior
- Acceptance criteria

### Bug Reports
Include:
- CLI version (`aiscan version`)
- Operating system
- Command executed
- Error message
- Steps to reproduce

---

**Built with ❤️ using C#, .NET 8, Claude AI, and Spectre.Console**

*The AI Security Scanner CLI: Making security scanning intelligent, accessible, and developer-friendly.*