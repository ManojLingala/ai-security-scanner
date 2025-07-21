# AI Security Scanner

A comprehensive AI-powered security vulnerability scanner for code repositories built with ASP.NET Core 8, featuring multi-AI provider support, real-time scanning capabilities, and compliance reporting.

## 🚀 Features

### Core Functionality
- **Multi-AI Provider Support**: Integration with OpenAI GPT-4 and Anthropic Claude for enhanced vulnerability detection
- **Static Code Analysis**: Roslyn-based C# code analysis with custom security rules
- **Real-time Scanning**: SignalR integration for live scan progress updates
- **Vulnerability Management**: Comprehensive vulnerability tracking, classification, and remediation
- **Advanced Compliance Framework**: Support for PCI DSS v4.0, HIPAA Security Rule, SOX, GDPR, plus OWASP, CWE, NIST, ISO27001, and SOC2 standards
- **Real-time Compliance Monitoring**: FileSystemWatcher-based monitoring for continuous compliance validation
- **Compliance Dashboard**: Comprehensive scoring, violation tracking, and remediation guidance

### Enterprise Features
- **Multi-tenant Architecture**: Organization-based isolation with usage quotas
- **Team Management**: Role-based access control (Admin, Developer, Viewer)
- **Usage Monitoring**: Track scans, users, and repositories with limits
- **Activity Logging**: Comprehensive audit trail for all system activities

### Technical Architecture
- **Clean Architecture**: Domain-driven design with clear separation of concerns
- **RavenDB**: Document database for flexible data modeling
- **JWT Authentication**: Secure token-based authentication
- **RESTful API**: Comprehensive REST API with Swagger documentation
- **Logging**: Structured logging with Serilog

## 🏗️ Architecture

```
AISecurityScanner/
├── src/
│   ├── AISecurityScanner.Domain/          # Domain entities and interfaces
│   ├── AISecurityScanner.Application/     # Business logic and services
│   ├── AISecurityScanner.Infrastructure/  # Data access and external services
│   └── AISecurityScanner.API/             # Web API controllers and configuration
└── tests/                                 # Unit and integration tests
```

### Domain Layer
- **Entities**: Organization, User, Repository, SecurityScan, Vulnerability, AIProvider
- **Enums**: VulnerabilitySeverity, ScanStatus, UserRole, ComplianceStandard
- **Interfaces**: Repository contracts and domain services

### Application Layer
- **Services**: SecurityScannerService, VulnerabilityAnalysisService, TeamManagementService
- **DTOs**: Data transfer objects for API communication
- **Validators**: FluentValidation rules for input validation
- **Mappings**: AutoMapper profiles for object mapping

### Infrastructure Layer
- **Data Access**: RavenDB repositories and Unit of Work pattern
- **AI Providers**: OpenAI and Anthropic Claude integrations
- **Code Analysis**: Static code analyzer using Roslyn
- **Compliance Providers**: PCI DSS v4.0, HIPAA, SOX, and GDPR compliance engines
- **Real-time Monitoring**: FileSystemWatcher-based compliance monitoring service
- **External Services**: HTTP clients and third-party integrations

### API Layer
- **Controllers**: REST endpoints for all operations
- **Authentication**: JWT Bearer token authentication
- **SignalR Hubs**: Real-time communication for scan updates
- **Middleware**: Error handling, logging, and CORS

## 📋 Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [RavenDB](https://ravendb.net/download) (Community Edition is sufficient)
- [Visual Studio 2022](https://visualstudio.microsoft.com/) or [VS Code](https://code.visualstudio.com/)
- AI Provider API Keys:
  - OpenAI API Key (optional)
  - Anthropic API Key (optional)

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone <repository-url>
cd AISecurityScanner
```

### 2. Setup RavenDB

#### Option A: Local Installation
1. Download and install RavenDB from [ravendb.net](https://ravendb.net/download)
2. Start RavenDB server (default: http://localhost:8080)
3. Create a database named `AISecurityScanner-Dev`

#### Option B: Docker
```bash
docker run -d --name ravendb -p 8080:8080 ravendb/ravendb
```

### 3. Configure Application Settings

Update `src/AISecurityScanner.API/appsettings.Development.json`:

```json
{
  "RavenDb": {
    "Urls": ["http://localhost:8080"],
    "Database": "AISecurityScanner-Dev",
    "UseEmbedded": false
  },
  "Jwt": {
    "Secret": "YourSecretKeyHereMustBeAtLeast256Bits12345!@#$%",
    "Issuer": "AISecurityScanner-Dev",
    "Audience": "AISecurityScanner-Dev",
    "ExpirationMinutes": 1440
  },
  "AIProviders": {
    "OpenAI": {
      "ApiKey": "your-openai-api-key-here",
      "Model": "gpt-4-turbo-preview"
    },
    "Claude": {
      "ApiKey": "your-anthropic-api-key-here",
      "Model": "claude-3-sonnet-20240229"
    }
  }
}
```

### 4. Build and Run

```bash
# Navigate to the API project
cd src/AISecurityScanner.API

# Restore dependencies
dotnet restore

# Build the application
dotnet build

# Run the application
dotnet run
```

The application will start at:
- **API**: http://localhost:5105
- **Swagger UI**: http://localhost:5105/swagger

## 📖 API Documentation

### Authentication

All API endpoints (except authentication) require a valid JWT token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

### Getting Started with the API

1. **Register/Login** to get a JWT token:
   ```
   POST /api/auth/login
   ```

2. **Create an Organization** (if you're an admin):
   ```
   POST /api/organizations
   ```

3. **Add a Repository** to scan:
   ```
   POST /api/repositories
   ```

4. **Start a Security Scan**:
   ```
   POST /api/scans/start
   ```

5. **Monitor Scan Progress** via SignalR:
   ```
   Connect to: /hubs/scanprogress
   ```

### Key Endpoints

#### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `POST /api/auth/refresh` - Refresh JWT token

#### Scans
- `GET /api/scans` - List scans
- `POST /api/scans/start` - Start new scan
- `GET /api/scans/{id}` - Get scan details
- `DELETE /api/scans/{id}` - Cancel scan

#### Repositories
- `GET /api/repositories` - List repositories
- `POST /api/repositories` - Add repository
- `PUT /api/repositories/{id}` - Update repository
- `DELETE /api/repositories/{id}` - Remove repository

#### Vulnerabilities
- `GET /api/vulnerabilities` - List vulnerabilities with filtering
- `GET /api/vulnerabilities/{id}` - Get vulnerability details
- `PUT /api/vulnerabilities/{id}/status` - Update vulnerability status
- `POST /api/vulnerabilities/{id}/false-positive` - Mark as false positive

#### Team Management
- `GET /api/teams/organization` - Get organization details
- `GET /api/teams/users` - List organization users
- `POST /api/teams/users` - Create user
- `POST /api/teams/invite` - Invite user

#### Compliance
- `GET /api/compliance/frameworks` - List supported compliance frameworks
- `POST /api/compliance/scan` - Start compliance scan
- `GET /api/compliance/scan/{id}` - Get compliance scan results
- `GET /api/compliance/violations` - List compliance violations
- `PUT /api/compliance/violations/{id}` - Update violation status
- `GET /api/compliance/dashboard/{framework}` - Get compliance dashboard
- `POST /api/compliance/export` - Export compliance report

## 🔧 CLI Architecture

The AI Security Scanner includes a comprehensive command-line interface (CLI) for developer workflows and CI/CD integration. The CLI provides a streamlined architecture that bypasses the full application layer for performance and simplicity.

### Command Translation Flow

```
User Input → CLI Parser → Command Handler → Services → AI Providers → Results → CLI Output
```

#### Example: File Scanning Command Flow

When you run `aiscan scan file UserController.cs --format json`, here's how it flows through the system:

1. **Command Parsing**: System.CommandLine parses the command into components
2. **Authentication Check**: Verifies stored Claude token and user consent
3. **Service Resolution**: Gets ScanService from dependency injection container
4. **File Processing**: Reads file content and detects programming language
5. **AI Analysis**: Calls Claude API directly with security analysis prompt
6. **Result Processing**: Parses AI response into SecurityVulnerability objects
7. **Output Formatting**: Displays results in requested format (table/json/csv)

#### CLI vs Full Application Architecture

| Aspect | CLI Approach | Full Application |
|--------|-------------|------------------|
| **Authentication** | Local config file (`~/.aiscan/config.json`) | JWT tokens + database |
| **Data Storage** | None (stateless) | RavenDB persistence |
| **Service Layer** | Direct AI provider calls | Layered architecture |
| **Startup Time** | Fast (~500ms) | Slower (~2-3s) |
| **Memory Usage** | Low (~50MB) | Higher (~150MB) |
| **Use Case** | Developer workflow | Enterprise platform |

#### Key Architectural Benefits

- **Performance**: Fast startup with minimal memory footprint
- **Simplicity**: Fewer dependencies and direct API calls
- **Portability**: Single binary deployment with no database setup
- **Developer Experience**: Immediate results with familiar CLI patterns

For detailed CLI architecture documentation, see [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md).

### CLI Installation and Usage

#### Quick Installation (Option 2 - Recommended for Developers)

**Prerequisites:**
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) installed
- [Claude Code CLI](https://claude.ai/code) installed and authenticated (or Claude API key)

**Step 1: Build and Install CLI Globally**
```bash
# Clone the repository
git clone <your-repository-url>
cd AISecurityScanner

# Navigate to CLI project
cd src/AISecurityScanner.CLI

# Build and package
dotnet build --configuration Release
dotnet pack --configuration Release

# Install globally
dotnet tool install --global --add-source ./bin/Release AISecurityScanner.CLI

# Verify installation
aiscan --help
aiscan version
```

**Step 2: Authenticate**
```bash
# Option A: Using Claude Code CLI (if installed)
aiscan auth login

# Option B: Manual API key entry (get key from https://console.anthropic.com/)
aiscan auth login
# Follow prompts to enter your Claude API key

# Verify authentication
aiscan auth status
```

**Step 3: Start Scanning**
```bash
# Scan a single file
aiscan scan file Controllers/UserController.cs

# Scan with different output formats
aiscan scan file Controllers/UserController.cs --format json
aiscan scan file Controllers/UserController.cs --format csv > results.csv

# Scan entire directory
aiscan scan directory ./src --format table

# Scan current project
aiscan scan project

# Run compliance scans
aiscan compliance list
aiscan compliance scan --framework pci-dss --path ./src
aiscan compliance scan --framework hipaa --format json
```

#### Available Commands Reference

**Authentication Commands:**
```bash
aiscan auth login          # Authenticate with Claude API
aiscan auth status         # Check authentication status  
aiscan auth logout         # Clear stored credentials
```

**Security Scanning Commands:**
```bash
aiscan scan file <path>                    # Scan single file
aiscan scan directory <path>               # Scan directory  
aiscan scan project                        # Scan current project
aiscan scan file <path> --format json     # JSON output
aiscan scan file <path> --format csv      # CSV output
aiscan scan directory <path> --recursive  # Recursive directory scan
```

**Compliance Scanning Commands:**
```bash
aiscan compliance list                                    # List all frameworks
aiscan compliance scan --framework pci-dss --path ./src  # PCI DSS scan
aiscan compliance scan --framework hipaa --format json   # HIPAA scan
aiscan compliance scan --framework sox --format csv      # SOX scan  
aiscan compliance scan --framework gdpr --path ./code    # GDPR scan
```

**Configuration Commands:**
```bash
aiscan config list                         # Show all settings
aiscan config get output_format            # Get specific setting
aiscan config set output_format json       # Set default format
aiscan config set scan_timeout 300         # Set scan timeout
```

#### Integration Examples

**Pre-commit Hook** (`.git/hooks/pre-commit`):
```bash
#!/bin/bash
# Scan staged files before commit
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(cs|js|ts|py|java)$')

for FILE in $STAGED_FILES; do
  echo "🔍 Scanning $FILE..."
  aiscan scan file "$FILE" --format json | jq -e '.vulnerabilities | length == 0' > /dev/null
  if [ $? -ne 0 ]; then
    echo "❌ Security vulnerabilities found in $FILE"
    aiscan scan file "$FILE"
    exit 1
  fi
done

echo "✅ Security scan passed!"
```

**GitHub Actions Integration:**
```yaml
- name: Security Scan
  run: |
    # Install CLI
    git clone <your-repo-url>
    cd AISecurityScanner/src/AISecurityScanner.CLI
    dotnet tool install --global --add-source ./bin/Release AISecurityScanner.CLI
    
    # Authenticate
    echo "${{ secrets.CLAUDE_API_KEY }}" | aiscan auth login --token-stdin
    
    # Run scans
    aiscan scan project --format json > security-results.json
    
    # Check for critical issues
    CRITICAL_COUNT=$(cat security-results.json | jq '[.vulnerabilities[] | select(.severity == "Critical")] | length')
    if [ "$CRITICAL_COUNT" -gt 0 ]; then
      echo "❌ Found $CRITICAL_COUNT critical vulnerabilities"
      exit 1
    fi
```

**CI/CD Pipeline Integration:**
```bash
# Build step
aiscan scan project --format json > security-report.json

# Quality gate
CRITICAL_COUNT=$(cat security-report.json | jq '[.vulnerabilities[] | select(.severity == "Critical")] | length')
HIGH_COUNT=$(cat security-report.json | jq '[.vulnerabilities[] | select(.severity == "High")] | length')

if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 5 ]; then
  echo "❌ Security quality gate failed"
  echo "Critical: $CRITICAL_COUNT, High: $HIGH_COUNT"
  exit 1
fi

echo "✅ Security quality gate passed"
```

#### Supported File Types and Languages

- **C#**: `.cs` files
- **JavaScript/TypeScript**: `.js`, `.ts` files  
- **Python**: `.py` files
- **Java**: `.java` files
- **C/C++**: `.c`, `.cpp`, `.cxx`, `.cc` files
- **PHP**: `.php` files
- **Configuration**: `.config`, `.json`, `.xml`, `.yml`, `.yaml` files
- **Database**: `.sql` files
- **Logs**: `.txt`, `.log` files

#### Output Formats

**Table Format (Default):**
```
🔍 Scanning file: Controllers/UserController.cs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Scan completed in 2.34s

🚨 High Severity (2 issues):
 -------------------------------------------------------------------------------
 | Line | Type              | Description                      | Confidence | CWE |
 -------------------------------------------------------------------------------
 | 42   | SQL Injection     | Unsanitized user input in query | 9.2        | 89  |
 | 67   | XSS               | Unencoded output to response     | 8.7        | 79  |
 -------------------------------------------------------------------------------
```

**JSON Format:**
```json
{
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "High", 
      "confidence": 9.2,
      "lineNumber": 42,
      "description": "Unsanitized user input in SQL query",
      "recommendation": "Use parameterized queries",
      "cweId": "CWE-89"
    }
  ]
}
```

**CSV Format:**
```csv
Line,Type,Severity,Description,Confidence,CWE,Recommendation
42,SQL Injection,High,"Unsanitized user input in query",9.2,89,"Use parameterized queries"
67,XSS,High,"Unencoded output to response",8.7,79,"Encode all user output"
```

#### Troubleshooting

**Common Issues:**

1. **CLI not found after installation:**
   ```bash
   # Ensure .NET tools directory is in PATH
   export PATH="$PATH:$HOME/.dotnet/tools"
   ```

2. **Authentication fails:**
   ```bash
   # Check your API key
   aiscan auth logout
   aiscan auth login
   
   # Verify connectivity
   curl -I https://api.anthropic.com/
   ```

3. **No files found for scanning:**
   ```bash
   # Check supported file types
   find . -name "*.cs" -o -name "*.js" -o -name "*.py"
   ```

4. **Permission errors:**
   ```bash
   # Check file permissions
   ls -la /path/to/files
   
   # Update CLI
   dotnet tool update --global aisecurityscanner.cli
   ```

For complete CLI documentation and advanced usage, see [CLI_USAGE.md](CLI_USAGE.md).

## 🔧 Configuration

### Environment Variables

You can override configuration using environment variables:

```bash
export RavenDb__Urls__0="http://localhost:8080"
export RavenDb__Database="AISecurityScanner-Prod"
export Jwt__Secret="your-production-secret-key"
export AIProviders__OpenAI__ApiKey="your-openai-key"
export AIProviders__Claude__ApiKey="your-anthropic-key"
```

### AI Provider Configuration

#### OpenAI Configuration
```json
{
  "AIProviders": {
    "OpenAI": {
      "ApiKey": "sk-...",
      "ApiEndpoint": "https://api.openai.com/v1/chat/completions",
      "Model": "gpt-4-turbo-preview",
      "MaxTokens": 4096,
      "CostPerRequest": 0.03
    }
  }
}
```

#### Anthropic Claude Configuration
```json
{
  "AIProviders": {
    "Claude": {
      "ApiKey": "sk-ant-...",
      "ApiEndpoint": "https://api.anthropic.com/v1/messages",
      "Model": "claude-3-sonnet-20240229",
      "MaxTokens": 4096,
      "CostPerRequest": 0.015
    }
  }
}
```

## 🛡️ Compliance Framework

The AI Security Scanner includes a comprehensive compliance framework supporting multiple industry standards:

### Supported Frameworks

#### PCI DSS v4.0 (Payment Card Industry Data Security Standard)
- **Network Security**: Firewall and system configuration rules
- **Cardholder Data Protection**: Encryption and storage requirements
- **Data Transmission Security**: TLS/SSL validation and secure protocols
- **Secure Development**: Input validation, XSS prevention, SQL injection detection
- **Access Control**: Authentication and authorization requirements
- **Audit Logging**: Comprehensive activity tracking
- **22 rules** covering all PCI DSS requirements

#### HIPAA Security Rule (Health Insurance Portability and Accountability Act)
- **Administrative Safeguards**: Security officer responsibilities and access management
- **Technical Safeguards**: Access control, audit controls, integrity, authentication, transmission security
- **Physical Safeguards**: Facility access, workstation security, device controls
- **PHI Detection**: Social Security Numbers, Medical Record Numbers, Date of Birth patterns
- **Information Disclosure**: Error handling and debug information protection
- **18 rules** covering all HIPAA Security Rule requirements

#### SOX (Sarbanes-Oxley Act)
- **Financial Reporting Controls**: Section 302 and 404 compliance
- **Internal Controls**: Documentation and testing requirements
- **Disclosure Controls**: Timely and accurate financial reporting
- **Document Retention**: Record keeping requirements
- **IT General Controls**: System access and change management
- **15 rules** covering key SOX IT requirements

#### GDPR (General Data Protection Regulation)
- **Data Processing Principles**: Lawful basis and data minimization
- **Consent Management**: Valid consent collection and withdrawal
- **Data Subject Rights**: Access, rectification, erasure, and portability
- **Privacy by Design**: Data protection impact assessments
- **Security Measures**: Encryption and pseudonymization
- **Breach Notification**: 72-hour notification requirements
- **21 rules** covering essential GDPR requirements

### Compliance Features

#### Real-time Monitoring
- **FileSystemWatcher Integration**: Continuous monitoring of code changes
- **Background Service**: Always-on compliance validation
- **Event-driven Architecture**: Immediate violation detection and notifications
- **Configurable Monitoring Paths**: Flexible directory and file monitoring

#### Compliance Dashboard
- **Overall Compliance Score**: Weighted scoring across all frameworks
- **Category Breakdown**: Detailed scores by compliance area
- **Violation Tracking**: Severity-based violation management
- **Trend Analysis**: Compliance score evolution over time
- **Executive Reporting**: High-level compliance status summaries

#### Violation Management
- **Severity Classification**: Critical, High, Medium, Low severity levels
- **Remediation Guidance**: Specific fix recommendations for each violation
- **Status Tracking**: Open, In Progress, Resolved, Accepted, False Positive
- **Evidence Collection**: Automatic collection of compliance evidence
- **Audit Trail**: Complete history of violation lifecycle

#### Export and Reporting
- **Multiple Formats**: JSON, XML, CSV, PDF report generation
- **Scheduled Reports**: Automated compliance reporting
- **Custom Report Templates**: Tailored reports for different stakeholders
- **Webhook Integration**: Real-time compliance notifications
- **API Access**: Programmatic access to compliance data

### Configuration Example

```json
{
  "Compliance": {
    "EnabledFrameworks": ["PCI_DSS", "HIPAA", "SOX", "GDPR"],
    "MonitoringPaths": [
      "/src",
      "/config",
      "/scripts"
    ],
    "RealTimeMonitoring": true,
    "ExportFormats": ["JSON", "PDF"],
    "WebhookUrl": "https://your-compliance-webhook.com/notifications"
  }
}
```

## 🧪 Testing

### Running Unit Tests

```bash
# Navigate to the solution root
cd AISecurityScanner

# Run all tests
dotnet test

# Run tests with coverage
dotnet test --collect:"XPlat Code Coverage"
```

### Manual Testing with Swagger

1. Start the application: `dotnet run`
2. Navigate to: http://localhost:5105/swagger
3. Use the "Authorize" button to add your JWT token
4. Test the various endpoints including new compliance features

### Sample Test Data

The application includes a data seeder that creates:
- Demo organization with subscription limits
- Sample users with different roles
- Test repositories
- Sample AI providers configuration

## 🔒 Security Features

### Authentication & Authorization
- JWT Bearer token authentication
- Role-based access control (Admin, Developer, Viewer)
- Organization-based data isolation
- Secure password handling (ready for bcrypt integration)

### Input Validation
- FluentValidation for all input models
- SQL injection prevention through parameterized queries
- XSS protection through proper encoding
- Rate limiting ready for implementation

### Data Security
- Audit trails for all modifications
- Soft delete for data retention
- Encrypted sensitive configuration values
- HTTPS enforcement

## 📊 Monitoring & Logging

### Structured Logging
- Serilog with structured logging
- File and console output
- Configurable log levels
- Request/response logging

### Health Checks
Ready for implementation:
- RavenDB connectivity
- AI provider availability
- System resource monitoring

## 🚀 Deployment Guide

### Option 1: CLI Tool Deployment (Recommended for Developers)

#### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) installed
- [Claude Code CLI](https://claude.ai/code) installed and authenticated
- Git for cloning the repository

#### Step 1: Clone and Build
```bash
# Clone the repository
git clone <your-repository-url>
cd AISecurityScanner

# Build the CLI
cd src/AISecurityScanner.CLI
dotnet build --configuration Release
```

#### Step 2: Install as Global Tool
```bash
# Package the CLI as a global tool
dotnet pack --configuration Release

# Install globally (replace version with actual version)
dotnet tool install --global --add-source ./bin/Release AISecurityScanner.CLI
```

#### Step 3: Verify Installation
```bash
# Test the installation
aiscan --help
aiscan version
```

### Option 2: Docker Deployment (Full API + CLI)

#### Step 1: Create Dockerfile
```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project files
COPY ["src/AISecurityScanner.API/AISecurityScanner.API.csproj", "src/AISecurityScanner.API/"]
COPY ["src/AISecurityScanner.CLI/AISecurityScanner.CLI.csproj", "src/AISecurityScanner.CLI/"]
COPY ["src/AISecurityScanner.Application/AISecurityScanner.Application.csproj", "src/AISecurityScanner.Application/"]
COPY ["src/AISecurityScanner.Domain/AISecurityScanner.Domain.csproj", "src/AISecurityScanner.Domain/"]
COPY ["src/AISecurityScanner.Infrastructure/AISecurityScanner.Infrastructure.csproj", "src/AISecurityScanner.Infrastructure/"]

# Restore dependencies
RUN dotnet restore "src/AISecurityScanner.API/AISecurityScanner.API.csproj"
RUN dotnet restore "src/AISecurityScanner.CLI/AISecurityScanner.CLI.csproj"

# Copy source code
COPY . .

# Build applications
RUN dotnet build "src/AISecurityScanner.API/AISecurityScanner.API.csproj" -c Release -o /app/api
RUN dotnet build "src/AISecurityScanner.CLI/AISecurityScanner.CLI.csproj" -c Release -o /app/cli

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# Install .NET SDK for CLI support
RUN apt-get update && apt-get install -y wget
RUN wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
RUN dpkg -i packages-microsoft-prod.deb
RUN apt-get update && apt-get install -y dotnet-sdk-8.0

# Copy applications
COPY --from=build /app/api ./api
COPY --from=build /app/cli ./cli

# Create symbolic link for CLI
RUN ln -s /app/cli/aiscan /usr/local/bin/aiscan

# Expose ports
EXPOSE 5105

# Set environment variables
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:5105

# Default to API, but allow CLI usage
ENTRYPOINT ["dotnet", "/app/api/AISecurityScanner.API.dll"]
```

#### Step 2: Create Docker Compose
```yaml
version: '3.8'

services:
  ravendb:
    image: ravendb/ravendb:5.4-ubuntu-latest
    ports:
      - "8080:8080"
    environment:
      - RAVEN_Setup_Mode=None
      - RAVEN_Security_UnsecuredAccessAllowed=PublicNetwork
    volumes:
      - ravendb_data:/opt/RavenDB/Server/RavenData

  aisecurityscanner:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "5105:5105"
    environment:
      - RavenDb__Urls__0=http://ravendb:8080
      - RavenDb__Database=AISecurityScanner-Prod
      - Jwt__Secret=YourProductionSecretKeyMustBeAtLeast256BitsLong!
      - AIProviders__Claude__ApiKey=${CLAUDE_API_KEY}
    depends_on:
      - ravendb
    volumes:
      - ./scans:/app/scans  # Volume for scan results
      
volumes:
  ravendb_data:
```

#### Step 3: Deploy with Docker
```bash
# Set your Claude API key
export CLAUDE_API_KEY="your-claude-api-key-here"

# Build and start services
docker-compose up --build -d

# Verify deployment
curl http://localhost:5105/api/health
```

### Option 3: Kubernetes Deployment

#### Step 1: Create Kubernetes Manifests
```yaml
# kubernetes/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: aisecurityscanner
---
# kubernetes/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aiscan-config
  namespace: aisecurityscanner
data:
  appsettings.json: |
    {
      "RavenDb": {
        "Urls": ["http://ravendb-service:8080"],
        "Database": "AISecurityScanner-Prod"
      },
      "Jwt": {
        "Issuer": "AISecurityScanner-Prod",
        "Audience": "AISecurityScanner-Prod",
        "ExpirationMinutes": 1440
      }
    }
---
# kubernetes/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: aiscan-secrets
  namespace: aisecurityscanner
type: Opaque
data:
  jwt-secret: WW91clByb2R1Y3Rpb25TZWNyZXRLZXlNdXN0QmVBdExlYXN0MjU2Qml0c0xvbmch  # Base64 encoded
  claude-api-key: c2stYW50LXlvdXItY2xhdWRlLWFwaS1rZXktaGVyZQ==  # Base64 encoded
---
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aisecurityscanner
  namespace: aisecurityscanner
spec:
  replicas: 3
  selector:
    matchLabels:
      app: aisecurityscanner
  template:
    metadata:
      labels:
        app: aisecurityscanner
    spec:
      containers:
      - name: aisecurityscanner
        image: your-registry/aisecurityscanner:latest
        ports:
        - containerPort: 5105
        env:
        - name: ASPNETCORE_ENVIRONMENT
          value: "Production"
        - name: Jwt__Secret
          valueFrom:
            secretKeyRef:
              name: aiscan-secrets
              key: jwt-secret
        - name: AIProviders__Claude__ApiKey
          valueFrom:
            secretKeyRef:
              name: aiscan-secrets
              key: claude-api-key
        volumeMounts:
        - name: config-volume
          mountPath: /app/appsettings.Production.json
          subPath: appsettings.json
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config-volume
        configMap:
          name: aiscan-config
---
# kubernetes/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: aisecurityscanner-service
  namespace: aisecurityscanner
spec:
  selector:
    app: aisecurityscanner
  ports:
  - protocol: TCP
    port: 80
    targetPort: 5105
  type: LoadBalancer
```

#### Step 2: Deploy to Kubernetes
```bash
# Apply manifests
kubectl apply -f kubernetes/

# Check deployment status
kubectl get pods -n aisecurityscanner
kubectl get services -n aisecurityscanner

# Get external IP
kubectl get service aisecurityscanner-service -n aisecurityscanner
```

## 📖 User Guide: How to Run Security Scanning

### For Developers (CLI Workflow)

#### Step 1: Initial Setup
```bash
# Authenticate with Claude Code
aiscan auth login

# Verify authentication
aiscan auth status
```

#### Step 2: Scan a Single File
```bash
# Basic file scan
aiscan scan file src/Controllers/UserController.cs

# With custom output format
aiscan scan file src/Controllers/UserController.cs --format json

# Save results to file
aiscan scan file src/Controllers/UserController.cs --format json > security-report.json
```

#### Step 3: Scan Entire Project
```bash
# Scan current project
aiscan scan project

# Scan specific directory
aiscan scan directory ./src --format table

# Recursive directory scan with CSV output
aiscan scan directory ./src --recursive --format csv > full-scan.csv
```

#### Step 4: Compliance Scanning
```bash
# List available frameworks
aiscan compliance list

# Run PCI DSS compliance scan
aiscan compliance scan --framework pci-dss --path ./src

# Multiple compliance scans
aiscan compliance scan --framework hipaa --path ./src --format json
aiscan compliance scan --framework gdpr --path ./src --format json
aiscan compliance scan --framework sox --path ./src --format json
```

### For Teams (API Workflow)

#### Step 1: Access Swagger UI
1. Navigate to: `http://your-domain:5105/swagger`
2. Click "Authorize" button
3. Enter your JWT token: `Bearer your-jwt-token`

#### Step 2: Register Organization
```bash
# Register new user and organization
curl -X POST "http://your-domain:5105/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourcompany.com",
    "password": "SecurePassword123!",
    "firstName": "Admin",
    "lastName": "User",
    "organizationName": "Your Company"
  }'
```

#### Step 3: Add Repository
```bash
# Login to get JWT token
TOKEN=$(curl -X POST "http://your-domain:5105/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourcompany.com","password":"SecurePassword123!"}' \
  | jq -r '.token')

# Add repository
curl -X POST "http://your-domain:5105/api/repositories" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Project",
    "gitUrl": "https://github.com/yourcompany/project.git",
    "branch": "main",
    "language": "CSharp"
  }'
```

#### Step 4: Start Security Scan
```bash
# Start scan (replace {repositoryId} with actual ID)
SCAN_ID=$(curl -X POST "http://your-domain:5105/api/scans/start" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "repositoryId": "repository-guid-here",
    "scanType": "Full",
    "includeAIAnalysis": true
  }' | jq -r '.scanId')

# Monitor scan progress
curl -X GET "http://your-domain:5105/api/scans/$SCAN_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### CI/CD Integration Examples

#### GitHub Actions
```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup .NET
      uses: actions/setup-dotnet@v4
      with:
        dotnet-version: '8.0.x'
        
    - name: Install AI Security Scanner CLI
      run: |
        git clone https://github.com/yourcompany/AISecurityScanner.git
        cd AISecurityScanner/src/AISecurityScanner.CLI
        dotnet build --configuration Release
        dotnet tool install --global --add-source ./bin/Release AISecurityScanner.CLI
        
    - name: Authenticate CLI
      env:
        CLAUDE_TOKEN: ${{ secrets.CLAUDE_API_KEY }}
      run: |
        echo "$CLAUDE_TOKEN" | aiscan auth login --token-stdin
        
    - name: Run Security Scan
      run: |
        aiscan scan project --format json > security-results.json
        
    - name: Check for Critical Vulnerabilities
      run: |
        CRITICAL_COUNT=$(cat security-results.json | jq '[.vulnerabilities[] | select(.severity == "Critical")] | length')
        if [ "$CRITICAL_COUNT" -gt 0 ]; then
          echo "❌ Found $CRITICAL_COUNT critical vulnerabilities"
          cat security-results.json | jq '.vulnerabilities[] | select(.severity == "Critical")'
          exit 1
        fi
        echo "✅ No critical vulnerabilities found"
        
    - name: Run Compliance Scan
      run: |
        aiscan compliance scan --framework pci-dss --format json > compliance-results.json
        
    - name: Upload Results
      uses: actions/upload-artifact@v4
      with:
        name: security-scan-results
        path: |
          security-results.json
          compliance-results.json
```

#### Azure DevOps Pipeline
```yaml
# azure-pipelines.yml
trigger:
- main
- develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  buildConfiguration: 'Release'

steps:
- task: UseDotNet@2
  displayName: 'Use .NET 8 SDK'
  inputs:
    packageType: 'sdk'
    version: '8.0.x'

- script: |
    git clone https://github.com/yourcompany/AISecurityScanner.git
    cd AISecurityScanner/src/AISecurityScanner.CLI
    dotnet build --configuration $(buildConfiguration)
    dotnet tool install --global --add-source ./bin/Release AISecurityScanner.CLI
  displayName: 'Install AI Security Scanner CLI'

- script: |
    echo "$(CLAUDE_API_KEY)" | aiscan auth login --token-stdin
  displayName: 'Authenticate CLI'
  env:
    CLAUDE_API_KEY: $(CLAUDE_API_KEY)

- script: |
    aiscan scan project --format json > $(Agent.TempDirectory)/security-results.json
  displayName: 'Run Security Scan'

- script: |
    CRITICAL_COUNT=$(cat $(Agent.TempDirectory)/security-results.json | jq '[.vulnerabilities[] | select(.severity == "Critical")] | length')
    if [ "$CRITICAL_COUNT" -gt 0 ]; then
      echo "##vso[task.logissue type=error]Found $CRITICAL_COUNT critical vulnerabilities"
      exit 1
    fi
    echo "✅ No critical vulnerabilities found"
  displayName: 'Check Security Results'

- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: '$(Agent.TempDirectory)/security-results.json'
    testRunTitle: 'Security Scan Results'
```

### Production Configuration

#### Environment Variables
```bash
# Required for production
export ASPNETCORE_ENVIRONMENT=Production
export RavenDb__Urls__0="https://your-ravendb-cluster.com"
export RavenDb__Database="AISecurityScanner-Prod"
export Jwt__Secret="Your-Super-Secure-256-Bit-Secret-Key-Here!"
export AIProviders__Claude__ApiKey="your-production-claude-key"

# Optional for enhanced security
export Jwt__Issuer="your-domain.com"
export Jwt__Audience="your-app-name"
export Jwt__ExpirationMinutes=60
```

#### SSL/HTTPS Configuration
```json
{
  "Kestrel": {
    "Endpoints": {
      "Https": {
        "Url": "https://+:5105",
        "Certificate": {
          "Path": "/app/certificates/cert.pfx",
          "Password": "certificate-password"
        }
      }
    }
  }
}
```

### Monitoring and Maintenance

#### Health Checks
```bash
# API health
curl https://your-domain:5105/api/health

# Database connectivity
curl https://your-domain:5105/api/health/db

# AI provider availability
curl https://your-domain:5105/api/health/ai
```

#### Log Monitoring
```bash
# View application logs
docker logs aisecurityscanner-container

# Follow real-time logs
docker logs -f aisecurityscanner-container

# Export logs for analysis
docker logs aisecurityscanner-container > app-logs.txt
```

#### Performance Monitoring
- Monitor API response times via health checks
- Track memory usage and CPU utilization
- Set up alerts for failed scans or high error rates
- Monitor RavenDB performance and storage usage

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

### Common Issues

**RavenDB Connection Issues**
- Verify RavenDB is running on the configured port
- Check firewall settings
- Ensure database exists

**AI Provider Errors**
- Verify API keys are valid and have sufficient quota
- Check network connectivity to AI provider endpoints
- Review rate limiting settings

**Authentication Issues**
- Ensure JWT secret is properly configured
- Check token expiration settings
- Verify CORS configuration for frontend integration

### Getting Help

- Check the [Issues](../../issues) section for known problems
- Review the [API documentation](http://localhost:5105/swagger) for endpoint details
- Check application logs in the `logs/` directory

## 🗺️ Roadmap

### Upcoming Features
- [ ] GitHub/GitLab integration for automatic repository scanning
- [ ] Package vulnerability detection (NuGet, npm, etc.)
- [ ] Advanced reporting and analytics dashboard
- [ ] Webhook support for CI/CD integration
- [ ] Machine learning model for custom vulnerability detection
- [ ] Mobile app for scan notifications
- [x] **Advanced compliance frameworks (PCI DSS v4.0, HIPAA, SOX, GDPR)** ✅
- [ ] Additional compliance frameworks (FedRAMP, CCPA, ISO 27001)
- [ ] Compliance trend analysis and forecasting
- [ ] Automated compliance remediation suggestions

### Performance Improvements
- [ ] Background job processing with Hangfire
- [ ] Caching layer with Redis
- [ ] Database query optimization
- [ ] Horizontal scaling support

---

## 📈 Architecture Decisions

### Why RavenDB?
- **Flexibility**: Document model adapts well to evolving vulnerability schemas
- **Performance**: Excellent read performance for analytics queries
- **Ease of Use**: LINQ support and automatic indexing
- **Scalability**: Built-in sharding and replication

### Why Clean Architecture?
- **Maintainability**: Clear separation of concerns
- **Testability**: Easy to unit test business logic
- **Flexibility**: Easy to swap implementations (database, AI providers)
- **Scalability**: Supports microservices evolution

### Why Multi-AI Providers?
- **Reliability**: Fallback options if one provider is unavailable
- **Cost Optimization**: Use different providers for different scan types
- **Quality**: Combine results from multiple AI models for better accuracy
- **Vendor Independence**: Avoid lock-in to a single AI provider