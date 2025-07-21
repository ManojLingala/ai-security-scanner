# CLI Architecture: Command Translation Flow

This document explains how CLI commands are translated into service calls within the AI Security Scanner architecture.

## Overview

The CLI acts as a lightweight client that orchestrates calls to the underlying AI Security Scanner services. Here's how a command flows through the system:

```
User Input → CLI Parser → Command Handler → Services → AI Providers → Results → CLI Output
```

## Example: File Scanning Command

Let's trace through a complete example: `aiscan scan file UserController.cs --format json`

### 1. Command Line Parsing
```bash
$ aiscan scan file UserController.cs --format json
```

**System.CommandLine** parses this into:
- Command: `scan`
- Subcommand: `file`
- Argument: `UserController.cs`
- Option: `--format json`

### 2. Command Handler Registration

In `Program.cs`, the command is registered:

```csharp
// Create file scan command
var fileCommand = new Command("file", "Scan a single file");
var filePathArgument = new Argument<string>("path", "Path to the file to scan");
var formatOption = new Option<string>("--format", getDefaultValue: () => "table");

fileCommand.AddArgument(filePathArgument);
fileCommand.AddOption(formatOption);

fileCommand.SetHandler(async (string path, string format) =>
{
    if (!await CheckAuthenticationAsync())
        return;

    var scanService = _serviceProvider!.GetRequiredService<ScanService>();
    var success = await scanService.ScanFileAsync(path, format);
    Environment.Exit(success ? 0 : 1);
}, filePathArgument, formatOption);
```

### 3. Dependency Injection Setup

The CLI configures minimal services needed for operation:

```csharp
private static IServiceCollection ConfigureServices()
{
    var services = new ServiceCollection();

    // Configuration
    services.AddSingleton<IConfiguration>(configuration);
    
    // Logging (minimal for CLI)
    services.AddLogging(builder => builder.SetMinimumLevel(LogLevel.Warning));

    // CLI Services
    services.AddScoped<ConfigService>();      // Manages ~/.aiscan/config.json
    services.AddScoped<AuthService>();        // Handles authentication
    services.AddScoped<ScanService>();        // Orchestrates scanning
    services.AddScoped<ComplianceCliService>(); // Handles compliance scans

    // AI Providers (direct usage for CLI)
    services.AddScoped<ClaudeProvider>();
    services.AddScoped<IAIProvider>(provider => provider.GetRequiredService<ClaudeProvider>());

    return services;
}
```

### 4. Authentication Check

Before executing the scan, the CLI verifies authentication:

```csharp
private static async Task<bool> CheckAuthenticationAsync()
{
    var authService = _serviceProvider!.GetRequiredService<AuthService>();
    
    if (!await authService.IsAuthenticatedAsync())
    {
        Console.WriteLine("❌ You are not authenticated.");
        Console.WriteLine("Run 'aiscan auth login' to authenticate first.");
        return false;
    }
    
    return true;
}
```

This checks `~/.aiscan/config.json` for stored Claude token and user consent.

### 5. ScanService Execution

The `ScanService.ScanFileAsync()` method orchestrates the actual scanning:

```csharp
public async Task<bool> ScanFileAsync(string filePath, string outputFormat = "table")
{
    // 1. Validate file exists
    if (!File.Exists(filePath))
    {
        Console.WriteLine($"❌ File not found: {filePath}");
        return false;
    }

    // 2. Read file content
    var fileContent = await File.ReadAllTextAsync(filePath);
    var fileExtension = Path.GetExtension(filePath);
    var language = DetectLanguage(fileExtension);

    // 3. Create AI analysis context
    var context = new AIAnalysisContext
    {
        Language = language,
        OrganizationId = Guid.NewGuid(), // CLI mode uses temp org
        IncludeAIDetection = true,
        IncludePackageValidation = false
    };

    // 4. Call AI Provider directly
    var result = await _aiProvider.AnalyzeCodeAsync(fileContent, context);
    
    // 5. Display results
    if (result.DetectedVulnerabilities.Any())
    {
        await DisplayVulnerabilities(result.DetectedVulnerabilities, outputFormat);
    }
    else
    {
        Console.WriteLine("🎉 No security vulnerabilities detected!");
    }

    return true;
}
```

### 6. AI Provider Integration

The CLI uses AI providers directly, bypassing the full application layer:

```csharp
// In ConfigService - retrieves stored Claude token
public async Task<string?> GetClaudeTokenAsync()
{
    var config = await GetConfigAsync();
    return config.ClaudeToken;
}

// ClaudeProvider uses the token for API calls
public async Task<SecurityAnalysisResult> AnalyzeCodeAsync(string code, AIAnalysisContext context)
{
    var token = await _configService.GetClaudeTokenAsync();
    
    // Build prompt for Claude API
    var prompt = BuildSecurityAnalysisPrompt(code, context);
    
    // Make HTTP request to Claude API
    var httpRequest = new HttpRequestMessage(HttpMethod.Post, ApiEndpoint)
    {
        Headers = { Authorization = new AuthenticationHeaderValue("Bearer", token) },
        Content = new StringContent(JsonSerializer.Serialize(new { prompt }), Encoding.UTF8, "application/json")
    };
    
    var response = await _httpClient.SendAsync(httpRequest);
    var responseContent = await response.Content.ReadAsStringAsync();
    
    // Parse AI response into vulnerabilities
    var vulnerabilities = ParseVulnerabilities(responseContent, context);
    
    return new SecurityAnalysisResult
    {
        IsSuccess = true,
        DetectedVulnerabilities = vulnerabilities,
        ConfidenceScore = CalculateConfidence(vulnerabilities),
        ResponseTime = DateTime.UtcNow - startTime,
        ProviderName = "Claude"
    };
}
```

### 7. Output Formatting

Results are formatted based on the `--format` option:

```csharp
private async Task DisplayVulnerabilities(List<SecurityVulnerability> vulnerabilities, string outputFormat)
{
    switch (outputFormat.ToLower())
    {
        case "json":
            var json = JsonSerializer.Serialize(vulnerabilities, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine(json);
            break;
            
        case "csv":
            Console.WriteLine("Line,Type,Severity,Description,Confidence,CWE,Recommendation");
            foreach (var vuln in vulnerabilities)
            {
                Console.WriteLine($"{vuln.LineNumber},\"{vuln.Type}\",\"{vuln.Severity}\",\"{EscapeCsv(vuln.Description)}\",{vuln.Confidence:F1},\"{vuln.CweId}\",\"{EscapeCsv(vuln.Recommendation)}\"");
            }
            break;
            
        case "table":
        default:
            // Use ConsoleTables library for formatted output
            var table = new ConsoleTable("Line", "Type", "Description", "Confidence", "CWE");
            foreach (var vuln in vulnerabilities)
            {
                table.AddRow(vuln.LineNumber, vuln.Type, TruncateString(vuln.Description, 50), $"{vuln.Confidence:F1}", vuln.CweId ?? "N/A");
            }
            table.Write();
            break;
    }
}
```

## Complete Flow Diagram

```mermaid
graph TD
    A[User Types: aiscan scan file app.js --format json] --> B[System.CommandLine Parser]
    B --> C[Command Handler in Program.cs]
    C --> D[Authentication Check]
    D --> E{Authenticated?}
    E -->|No| F[Display Auth Error & Exit]
    E -->|Yes| G[Get ScanService from DI Container]
    G --> H[ScanService.ScanFileAsync()]
    H --> I[Read File Content]
    I --> J[Detect Programming Language]
    J --> K[Create AIAnalysisContext]
    K --> L[Get Claude Token from Config]
    L --> M[ClaudeProvider.AnalyzeCodeAsync()]
    M --> N[Build Security Analysis Prompt]
    N --> O[HTTP POST to Claude API]
    O --> P[Parse Claude Response]
    P --> Q[Convert to SecurityVulnerability Objects]
    Q --> R[Return SecurityAnalysisResult]
    R --> S[Format Output Based on --format Option]
    S --> T[Display Results to Console]
    T --> U[Exit with Success/Failure Code]
```

## Key Architectural Decisions

### 1. **Minimal Service Layer**
The CLI bypasses the full application layer (like `VulnerabilityAnalysisService`) and calls AI providers directly:

**Why?** 
- Reduces complexity for CLI-only operations
- Eliminates need for database dependencies (RavenDB)
- Faster startup and execution
- Simpler dependency injection setup

**Trade-off:**
- No data persistence (scans are not stored)
- No user/organization management
- No scan history or vulnerability tracking

### 2. **Direct AI Provider Usage**
```csharp
// CLI Approach (Direct)
services.AddScoped<ClaudeProvider>();
services.AddScoped<IAIProvider>(provider => provider.GetRequiredService<ClaudeProvider>());

// vs. Full Application Approach
services.AddScoped<IVulnerabilityAnalysisService, VulnerabilityAnalysisService>();
services.AddScoped<ISecurityScannerService, SecurityScannerService>();
```

### 3. **Configuration-based Authentication**
Instead of JWT tokens and user management, the CLI uses:
- Local config file (`~/.aiscan/config.json`)
- Direct Claude API token storage
- User consent tracking

### 4. **Stateless Operation**
Each CLI command is independent:
- No session management
- No scan history
- No user context
- Temporary organization IDs for AI context

## Compliance Scanning Example

Let's trace: `aiscan compliance scan --framework pci-dss --path ./src`

### 1. Command Setup
```csharp
var scanCommand = new Command("scan", "Run compliance scan");
var frameworkOption = new Option<string>("--framework", "Compliance framework") { IsRequired = true };
var pathOption = new Option<string>("--path", getDefaultValue: () => Directory.GetCurrentDirectory());

scanCommand.SetHandler(async (string framework, string path, string format) =>
{
    var complianceService = _serviceProvider!.GetRequiredService<ComplianceCliService>();
    var success = await complianceService.ScanComplianceAsync(framework, path, format);
}, frameworkOption, pathOption, formatOption);
```

### 2. Compliance Service Execution
```csharp
public async Task<bool> ScanComplianceAsync(string framework, string directoryPath, string outputFormat)
{
    // 1. Parse framework string to enum
    var frameworkType = ParseFramework(framework); // "pci-dss" → ComplianceFrameworkType.PCI_DSS
    
    // 2. Find all scannable files
    var files = GetComplianceFiles(directoryPath);
    
    // 3. Create scan context
    var scanContext = new ComplianceScanContext
    {
        ScanId = Guid.NewGuid(),
        OrganizationId = Guid.NewGuid(),
        Files = files
    };
    
    // 4. Create compliance provider directly (no factory needed for CLI)
    var provider = CreateComplianceProvider(frameworkType.Value);
    
    // 5. Run compliance scan
    var result = await provider.ScanAsync(scanContext);
    
    // 6. Display formatted results
    await DisplayComplianceResults(result, outputFormat);
}

private IComplianceProvider CreateComplianceProvider(ComplianceFrameworkType framework)
{
    return framework switch
    {
        ComplianceFrameworkType.PCI_DSS => new PCIDSSComplianceProvider(null!), // No logger for CLI
        ComplianceFrameworkType.HIPAA => new HIPAAComplianceProvider(null!),
        ComplianceFrameworkType.SOX => new SOXComplianceProvider(null!),
        ComplianceFrameworkType.GDPR => new GDPRComplianceProvider(null!),
        _ => throw new NotSupportedException($"Framework {framework} not supported")
    };
}
```

### 3. Compliance Provider Execution
The compliance providers work the same as in the full application:
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
            for (int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
            {
                if (rule.IsRegex ? Regex.IsMatch(lines[lineIndex], rule.Pattern) 
                                : lines[lineIndex].Contains(rule.Pattern))
                {
                    violations.Add(CreateViolation(rule, file, lineIndex + 1, lines[lineIndex]));
                }
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

## CLI vs Full Application Comparison

| Aspect | CLI Approach | Full Application |
|--------|-------------|------------------|
| **Authentication** | Local config file | JWT tokens + database |
| **Data Storage** | None (stateless) | RavenDB persistence |
| **User Management** | Single user | Multi-tenant organizations |
| **Scan History** | None | Full audit trail |
| **Service Layer** | Direct provider calls | Layered architecture |
| **Dependency Injection** | Minimal services | Full service registration |
| **Startup Time** | Fast (~500ms) | Slower (~2-3s) |
| **Memory Usage** | Low (~50MB) | Higher (~150MB) |
| **Use Case** | Developer workflow | Enterprise platform |

## Benefits of This Architecture

### 1. **Performance**
- Fast startup time
- Minimal memory footprint
- Direct API calls without database overhead

### 2. **Simplicity**
- Fewer moving parts
- Easier to debug
- Self-contained executable

### 3. **Portability**
- No database setup required
- Single binary deployment
- Works offline (except AI API calls)

### 4. **Developer Experience**
- Immediate results
- Clear command structure
- Familiar CLI patterns

## Future Enhancements

### 1. **Caching Layer**
```csharp
// Future: Cache scan results locally
public class ScanCacheService
{
    public async Task<SecurityAnalysisResult?> GetCachedResult(string fileHash);
    public async Task CacheResult(string fileHash, SecurityAnalysisResult result);
}
```

### 2. **Plugin System**
```csharp
// Future: Support for custom analyzers
public interface ICliPlugin
{
    Task<SecurityAnalysisResult> AnalyzeAsync(string code, PluginContext context);
}
```

### 3. **Configuration Profiles**
```csharp
// Future: Multiple configuration profiles
aiscan config profile create work --framework pci-dss,hipaa
aiscan config profile use work
```

This architecture provides a clean separation between the CLI interface and the underlying security scanning capabilities, making it both powerful and easy to use for developers.