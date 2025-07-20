using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.Extensions.Logging;
using AISecurityScanner.Application.DTOs;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Infrastructure.CodeAnalysis
{
    public interface IStaticCodeAnalyzer
    {
        Task<List<VulnerabilityDto>> AnalyzeCodeAsync(string code, string language, string fileName, CancellationToken cancellationToken = default);
        Task<bool> DetectAIGeneratedCodeAsync(string code, string language, CancellationToken cancellationToken = default);
    }

    public class StaticCodeAnalyzer : IStaticCodeAnalyzer
    {
        private readonly ILogger<StaticCodeAnalyzer> _logger;

        public StaticCodeAnalyzer(ILogger<StaticCodeAnalyzer> logger)
        {
            _logger = logger;
        }

        public async Task<List<VulnerabilityDto>> AnalyzeCodeAsync(string code, string language, string fileName, CancellationToken cancellationToken = default)
        {
            return language.ToLowerInvariant() switch
            {
                "c#" or "csharp" => await AnalyzeCSharpCodeAsync(code, fileName, cancellationToken),
                "javascript" or "js" => await AnalyzeJavaScriptCodeAsync(code, fileName, cancellationToken),
                "python" or "py" => await AnalyzePythonCodeAsync(code, fileName, cancellationToken),
                _ => await AnalyzeGenericCodeAsync(code, fileName, cancellationToken)
            };
        }

        public async Task<bool> DetectAIGeneratedCodeAsync(string code, string language, CancellationToken cancellationToken = default)
        {
            await Task.Yield(); // Make it async
            
            // AI code detection heuristics
            var aiIndicators = 0;
            var lines = code.Split('\n');

            // Check for common AI-generated patterns
            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();

                // AI often generates very descriptive comments
                if (trimmedLine.StartsWith("//") && trimmedLine.Length > 50)
                    aiIndicators++;

                // AI tends to use very descriptive variable names
                if (ContainsVerboseVariableNames(trimmedLine))
                    aiIndicators++;

                // AI often includes example values in comments
                if (trimmedLine.Contains("example") || trimmedLine.Contains("TODO") || trimmedLine.Contains("Replace with"))
                    aiIndicators++;

                // AI-generated code often has perfect formatting
                if (HasPerfectFormatting(trimmedLine))
                    aiIndicators++;
            }

            // Calculate AI probability
            var aiProbability = (double)aiIndicators / Math.Max(lines.Length, 1);
            return aiProbability > 0.3; // 30% threshold
        }

        private async Task<List<VulnerabilityDto>> AnalyzeCSharpCodeAsync(string code, string fileName, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityDto>();

            try
            {
                var tree = CSharpSyntaxTree.ParseText(code);
                var root = await tree.GetRootAsync(cancellationToken);

                // SQL Injection Detection
                vulnerabilities.AddRange(DetectSqlInjection(root, fileName));

                // Hard-coded Secrets Detection
                vulnerabilities.AddRange(DetectHardcodedSecrets(root, fileName));

                // Insecure Random Number Generation
                vulnerabilities.AddRange(DetectInsecureRandom(root, fileName));

                // Path Traversal
                vulnerabilities.AddRange(DetectPathTraversal(root, fileName));

                // Weak Cryptography
                vulnerabilities.AddRange(DetectWeakCryptography(root, fileName));

                // Command Injection
                vulnerabilities.AddRange(DetectCommandInjection(root, fileName));

                _logger.LogDebug("Analyzed C# file {FileName}, found {Count} vulnerabilities", fileName, vulnerabilities.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing C# code in file {FileName}", fileName);
            }

            return vulnerabilities;
        }

        private List<VulnerabilityDto> DetectSqlInjection(SyntaxNode root, string fileName)
        {
            var vulnerabilities = new List<VulnerabilityDto>();

            // Find string concatenations with SQL keywords
            var stringConcatenations = root.DescendantNodes()
                .OfType<BinaryExpressionSyntax>()
                .Where(b => b.OperatorToken.IsKind(SyntaxKind.PlusToken));

            foreach (var concat in stringConcatenations)
            {
                var text = concat.ToString();
                if (ContainsSqlKeywords(text) && ContainsVariableReference(text))
                {
                    vulnerabilities.Add(new VulnerabilityDto
                    {
                        Id = Guid.NewGuid(),
                        Type = "SQL Injection",
                        Severity = VulnerabilitySeverity.High,
                        FilePath = fileName,
                        LineNumber = concat.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        Description = "Potential SQL injection vulnerability due to string concatenation in SQL query",
                        Recommendation = "Use parameterized queries or prepared statements instead of string concatenation",
                        Confidence = 0.8m,
                        CWE = "CWE-89",
                        OWASPCategory = "A03:2021-Injection",
                        DetectionEngine = "Static Analysis",
                        Status = VulnerabilityStatus.Open,
                        CreatedAt = DateTime.UtcNow
                    });
                }
            }

            return vulnerabilities;
        }

        private List<VulnerabilityDto> DetectHardcodedSecrets(SyntaxNode root, string fileName)
        {
            var vulnerabilities = new List<VulnerabilityDto>();

            var literals = root.DescendantNodes()
                .OfType<LiteralExpressionSyntax>()
                .Where(l => l.Token.IsKind(SyntaxKind.StringLiteralToken));

            foreach (var literal in literals)
            {
                var value = literal.Token.ValueText;
                if (IsLikelySecret(value))
                {
                    var parent = literal.Parent;
                    var variableName = GetVariableName(parent);

                    vulnerabilities.Add(new VulnerabilityDto
                    {
                        Id = Guid.NewGuid(),
                        Type = "Hard-coded Secret",
                        Severity = VulnerabilitySeverity.Critical,
                        FilePath = fileName,
                        LineNumber = literal.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        Description = $"Hard-coded secret detected in variable '{variableName}'. This exposes sensitive information in source code.",
                        Recommendation = "Use environment variables, configuration files, or secure key management systems",
                        Confidence = 0.9m,
                        CWE = "CWE-798",
                        OWASPCategory = "A07:2021-Identification and Authentication Failures",
                        DetectionEngine = "Static Analysis",
                        Status = VulnerabilityStatus.Open,
                        CreatedAt = DateTime.UtcNow
                    });
                }
            }

            return vulnerabilities;
        }

        private List<VulnerabilityDto> DetectInsecureRandom(SyntaxNode root, string fileName)
        {
            var vulnerabilities = new List<VulnerabilityDto>();

            var memberAccess = root.DescendantNodes()
                .OfType<MemberAccessExpressionSyntax>()
                .Where(m => m.Expression.ToString().Contains("Random") || m.Name.ToString().Contains("Random"));

            foreach (var member in memberAccess)
            {
                if (member.Expression.ToString() == "System.Random" || member.Expression.ToString() == "Random")
                {
                    vulnerabilities.Add(new VulnerabilityDto
                    {
                        Id = Guid.NewGuid(),
                        Type = "Weak Random Number Generation",
                        Severity = VulnerabilitySeverity.Medium,
                        FilePath = fileName,
                        LineNumber = member.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        Description = "Use of System.Random for security-sensitive operations is not cryptographically secure",
                        Recommendation = "Use System.Security.Cryptography.RandomNumberGenerator for cryptographic purposes",
                        Confidence = 0.7m,
                        CWE = "CWE-338",
                        OWASPCategory = "A02:2021-Cryptographic Failures",
                        DetectionEngine = "Static Analysis",
                        Status = VulnerabilityStatus.Open,
                        CreatedAt = DateTime.UtcNow
                    });
                }
            }

            return vulnerabilities;
        }

        private List<VulnerabilityDto> DetectPathTraversal(SyntaxNode root, string fileName)
        {
            var vulnerabilities = new List<VulnerabilityDto>();

            var methodInvocations = root.DescendantNodes()
                .OfType<InvocationExpressionSyntax>()
                .Where(i => i.Expression.ToString().Contains("Path.Combine") || 
                           i.Expression.ToString().Contains("File."));

            foreach (var invocation in methodInvocations)
            {
                var args = invocation.ArgumentList.Arguments;
                if (args.Any(arg => ContainsUserInput(arg.ToString())))
                {
                    vulnerabilities.Add(new VulnerabilityDto
                    {
                        Id = Guid.NewGuid(),
                        Type = "Path Traversal",
                        Severity = VulnerabilitySeverity.High,
                        FilePath = fileName,
                        LineNumber = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        Description = "Potential path traversal vulnerability - user input used in file path operations",
                        Recommendation = "Validate and sanitize file paths, use Path.GetFullPath() and check against allowed directories",
                        Confidence = 0.6m,
                        CWE = "CWE-22",
                        OWASPCategory = "A01:2021-Broken Access Control",
                        DetectionEngine = "Static Analysis",
                        Status = VulnerabilityStatus.Open,
                        CreatedAt = DateTime.UtcNow
                    });
                }
            }

            return vulnerabilities;
        }

        private List<VulnerabilityDto> DetectWeakCryptography(SyntaxNode root, string fileName)
        {
            var vulnerabilities = new List<VulnerabilityDto>();

            var identifiers = root.DescendantNodes()
                .OfType<IdentifierNameSyntax>()
                .Where(i => IsWeakCryptographicAlgorithm(i.Identifier.ValueText));

            foreach (var identifier in identifiers)
            {
                vulnerabilities.Add(new VulnerabilityDto
                {
                    Id = Guid.NewGuid(),
                    Type = "Weak Cryptographic Algorithm",
                    Severity = VulnerabilitySeverity.High,
                    FilePath = fileName,
                    LineNumber = identifier.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                    Description = $"Use of weak cryptographic algorithm: {identifier.Identifier.ValueText}",
                    Recommendation = "Use strong cryptographic algorithms like AES-256, SHA-256, or RSA with appropriate key sizes",
                    Confidence = 0.9m,
                    CWE = "CWE-327",
                    OWASPCategory = "A02:2021-Cryptographic Failures",
                    DetectionEngine = "Static Analysis",
                    Status = VulnerabilityStatus.Open,
                    CreatedAt = DateTime.UtcNow
                });
            }

            return vulnerabilities;
        }

        private List<VulnerabilityDto> DetectCommandInjection(SyntaxNode root, string fileName)
        {
            var vulnerabilities = new List<VulnerabilityDto>();

            var invocations = root.DescendantNodes()
                .OfType<InvocationExpressionSyntax>()
                .Where(i => i.Expression.ToString().Contains("Process.Start") ||
                           i.Expression.ToString().Contains("Command") ||
                           i.Expression.ToString().Contains("Exec"));

            foreach (var invocation in invocations)
            {
                var args = invocation.ArgumentList.Arguments;
                if (args.Any(arg => ContainsStringConcatenation(arg.ToString())))
                {
                    vulnerabilities.Add(new VulnerabilityDto
                    {
                        Id = Guid.NewGuid(),
                        Type = "Command Injection",
                        Severity = VulnerabilitySeverity.Critical,
                        FilePath = fileName,
                        LineNumber = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        Description = "Potential command injection through unsanitized input in process execution",
                        Recommendation = "Use parameterized process execution, validate input, or use safer alternatives",
                        Confidence = 0.7m,
                        CWE = "CWE-78",
                        OWASPCategory = "A03:2021-Injection",
                        DetectionEngine = "Static Analysis",
                        Status = VulnerabilityStatus.Open,
                        CreatedAt = DateTime.UtcNow
                    });
                }
            }

            return vulnerabilities;
        }

        private async Task<List<VulnerabilityDto>> AnalyzeJavaScriptCodeAsync(string code, string fileName, CancellationToken cancellationToken)
        {
            await Task.Yield();
            var vulnerabilities = new List<VulnerabilityDto>();

            // Basic JavaScript vulnerability detection
            var lines = code.Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].Trim();

                // XSS vulnerabilities
                if (line.Contains("innerHTML") && line.Contains("+"))
                {
                    vulnerabilities.Add(CreateVulnerability("Cross-Site Scripting (XSS)", 
                        VulnerabilitySeverity.High, fileName, i + 1,
                        "Potential XSS vulnerability using innerHTML with concatenated content",
                        "Use textContent or properly escape HTML content"));
                }

                // eval() usage
                if (line.Contains("eval("))
                {
                    vulnerabilities.Add(CreateVulnerability("Code Injection", 
                        VulnerabilitySeverity.Critical, fileName, i + 1,
                        "Use of eval() can lead to code injection vulnerabilities",
                        "Avoid eval() and use safer alternatives like JSON.parse()"));
                }
            }

            return vulnerabilities;
        }

        private async Task<List<VulnerabilityDto>> AnalyzePythonCodeAsync(string code, string fileName, CancellationToken cancellationToken)
        {
            await Task.Yield();
            var vulnerabilities = new List<VulnerabilityDto>();

            var lines = code.Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].Trim();

                // exec() or eval() usage
                if (line.Contains("exec(") || line.Contains("eval("))
                {
                    vulnerabilities.Add(CreateVulnerability("Code Injection", 
                        VulnerabilitySeverity.Critical, fileName, i + 1,
                        "Use of exec() or eval() can lead to code injection",
                        "Avoid dynamic code execution or properly sanitize input"));
                }

                // SQL injection patterns
                if (line.Contains("execute(") && line.Contains("%") && line.Contains("\""))
                {
                    vulnerabilities.Add(CreateVulnerability("SQL Injection", 
                        VulnerabilitySeverity.High, fileName, i + 1,
                        "Potential SQL injection through string formatting",
                        "Use parameterized queries or prepared statements"));
                }
            }

            return vulnerabilities;
        }

        private async Task<List<VulnerabilityDto>> AnalyzeGenericCodeAsync(string code, string fileName, CancellationToken cancellationToken)
        {
            await Task.Yield();
            var vulnerabilities = new List<VulnerabilityDto>();

            // Generic pattern detection
            var lines = code.Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].Trim().ToLowerInvariant();

                // Hard-coded credentials
                if ((line.Contains("password") || line.Contains("apikey") || line.Contains("secret")) && 
                    line.Contains("=") && line.Contains("\""))
                {
                    vulnerabilities.Add(CreateVulnerability("Hard-coded Credentials", 
                        VulnerabilitySeverity.Critical, fileName, i + 1,
                        "Hard-coded credentials detected",
                        "Use environment variables or secure configuration"));
                }
            }

            return vulnerabilities;
        }

        private VulnerabilityDto CreateVulnerability(string type, VulnerabilitySeverity severity, 
            string fileName, int lineNumber, string description, string recommendation)
        {
            return new VulnerabilityDto
            {
                Id = Guid.NewGuid(),
                Type = type,
                Severity = severity,
                FilePath = fileName,
                LineNumber = lineNumber,
                Description = description,
                Recommendation = recommendation,
                Confidence = 0.6m,
                DetectionEngine = "Static Analysis",
                Status = VulnerabilityStatus.Open,
                CreatedAt = DateTime.UtcNow
            };
        }

        // Helper methods
        private bool ContainsSqlKeywords(string text)
        {
            var keywords = new[] { "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "ORDER BY" };
            return keywords.Any(k => text.Contains(k, StringComparison.OrdinalIgnoreCase));
        }

        private bool ContainsVariableReference(string text)
        {
            return text.Contains("+") || text.Contains("$") || text.Contains("{");
        }

        private bool IsLikelySecret(string value)
        {
            if (value.Length < 10) return false;
            
            var secretPatterns = new[]
            {
                @"^[A-Za-z0-9+/]{40,}={0,2}$", // Base64
                @"^[a-f0-9]{32,}$", // Hex
                @"^sk-[a-zA-Z0-9]{48}$", // OpenAI API key pattern
                @"^xoxb-[a-zA-Z0-9-]+$" // Slack token pattern
            };

            return secretPatterns.Any(pattern => System.Text.RegularExpressions.Regex.IsMatch(value, pattern));
        }

        private string GetVariableName(SyntaxNode? node)
        {
            if (node is VariableDeclaratorSyntax declarator)
                return declarator.Identifier.ValueText;
            
            if (node is AssignmentExpressionSyntax assignment)
                return assignment.Left.ToString();

            return "unknown";
        }

        private bool ContainsUserInput(string text)
        {
            var userInputIndicators = new[] { "Request.", "HttpContext.", "input", "parameter", "arg" };
            return userInputIndicators.Any(indicator => text.Contains(indicator, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsWeakCryptographicAlgorithm(string algorithm)
        {
            var weakAlgorithms = new[] { "MD5", "SHA1", "DES", "RC4", "RC2" };
            return weakAlgorithms.Any(weak => algorithm.Contains(weak, StringComparison.OrdinalIgnoreCase));
        }

        private bool ContainsStringConcatenation(string text)
        {
            return text.Contains("+") || text.Contains("$\"") || text.Contains("string.Format");
        }

        private bool ContainsVerboseVariableNames(string line)
        {
            // AI tends to use very descriptive variable names
            var words = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return words.Any(word => word.Length > 15 && char.IsLower(word[0]));
        }

        private bool HasPerfectFormatting(string line)
        {
            // AI-generated code often has consistent spacing and formatting
            if (string.IsNullOrWhiteSpace(line)) return false;
            
            // Check for consistent spacing around operators
            return line.Contains(" = ") || line.Contains(" + ") || line.Contains(" && ") || line.Contains(" || ");
        }
    }
}