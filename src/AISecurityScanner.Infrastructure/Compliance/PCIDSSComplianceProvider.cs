using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Enums;
using Microsoft.Extensions.Logging;

namespace AISecurityScanner.Infrastructure.Compliance
{
    public class PCIDSSComplianceProvider : IComplianceProvider
    {
        private readonly ILogger<PCIDSSComplianceProvider> _logger;
        private readonly Dictionary<string, List<ComplianceRule>> _complianceRules;

        public ComplianceFrameworkType Framework => ComplianceFrameworkType.PCI_DSS;
        public string Version => "4.0";
        public string Name => "PCI DSS v4.0";

        public PCIDSSComplianceProvider(ILogger<PCIDSSComplianceProvider> logger)
        {
            _logger = logger;
            _complianceRules = InitializePCIDSSRules();
        }

        public async Task<ComplianceScanResult> ScanAsync(ComplianceScanContext context, CancellationToken cancellationToken = default)
        {
            var startTime = DateTime.UtcNow;
            var violations = new List<ComplianceViolation>();
            var evidence = new List<ComplianceEvidence>();

            try
            {
                _logger.LogInformation("Starting PCI DSS v4.0 compliance scan for {FileCount} files", context.Files.Count);

                foreach (var file in context.Files)
                {
                    var fileViolations = await ScanFileAsync(file, cancellationToken);
                    violations.AddRange(fileViolations);

                    var fileEvidence = await CollectEvidenceAsync(file, cancellationToken);
                    evidence.AddRange(fileEvidence);
                }

                var scanResult = new ComplianceScanResult
                {
                    Id = Guid.NewGuid(),
                    ScanId = context.ScanId,
                    OrganizationId = context.OrganizationId,
                    Framework = Framework,
                    ScanDate = startTime,
                    ScanDuration = DateTime.UtcNow - startTime,
                    FilesScanned = context.Files.Count,
                    RulesEvaluated = _complianceRules.Values.Sum(rules => rules.Count),
                    Violations = violations,
                    Evidence = evidence,
                    OverallScore = CalculateComplianceScore(violations),
                    Recommendations = GenerateRecommendations(violations)
                };

                _logger.LogInformation("PCI DSS scan completed. Found {ViolationCount} violations", violations.Count);
                return scanResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during PCI DSS compliance scan");
                throw;
            }
        }

        private async Task<List<ComplianceViolation>> ScanFileAsync(ComplianceFile file, CancellationToken cancellationToken)
        {
            var violations = new List<ComplianceViolation>();
            var content = await file.ReadContentAsync();
            var lines = content.Split('\n');

            // Get applicable rules for this file type
            var applicableRules = GetApplicableRules(file.Extension);

            for (int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
            {
                var line = lines[lineIndex];
                
                foreach (var rule in applicableRules)
                {
                    bool hasMatch = false;
                    if (rule.IsRegex)
                    {
                        hasMatch = Regex.IsMatch(line, rule.Pattern, RegexOptions.IgnoreCase);
                    }
                    else
                    {
                        hasMatch = line.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase);
                    }

                    if (hasMatch)
                    {
                        var violation = CreateViolation(rule, file, lineIndex + 1, line);
                        violations.Add(violation);
                    }
                }
            }

            return violations;
        }

        private Dictionary<string, List<ComplianceRule>> InitializePCIDSSRules()
        {
            var rules = new Dictionary<string, List<ComplianceRule>>();

            // Requirement 1 & 2: Network Security and System Configuration
            rules["network_security"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-1.1",
                    Name = "Insecure Network Configuration",
                    Description = "Network configuration files should not contain default passwords or insecure settings",
                    Type = ComplianceRuleType.Configuration,
                    Pattern = @"(password\s*=\s*(admin|password|123456|default)|(ssl\s*=\s*false)|(secure\s*=\s*false))",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".config", ".xml", ".json", ".properties", ".yml", ".yaml" },
                    RemediationGuidance = "Remove default passwords and enable secure communication protocols",
                    References = new List<string> { "PCI DSS v4.0 Requirement 1", "PCI DSS v4.0 Requirement 2" }
                }
            };

            // Requirement 3: Protect Stored Cardholder Data
            rules["cardholder_data"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-3.1",
                    Name = "Unencrypted Cardholder Data Storage",
                    Description = "Credit card numbers must be encrypted when stored",
                    Type = ComplianceRuleType.DataClassification,
                    Pattern = @"(credit_card|creditcard|ccnumber|card_number|pan)\s*[:=]\s*['""]?(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{15,16})['""]?",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".php", ".sql" },
                    RemediationGuidance = "Encrypt cardholder data using strong encryption algorithms (AES-256)",
                    References = new List<string> { "PCI DSS v4.0 Requirement 3.3", "PCI DSS v4.0 Requirement 3.4" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-3.2",
                    Name = "Credit Card Pattern in Code",
                    Description = "Credit card numbers detected in source code or configuration",
                    Type = ComplianceRuleType.DataClassification,
                    Pattern = @"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".php", ".txt", ".log", ".sql", ".xml", ".json" },
                    RemediationGuidance = "Remove credit card numbers from source code and logs. Use tokenization for testing.",
                    References = new List<string> { "PCI DSS v4.0 Requirement 3.3" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-3.3",
                    Name = "Weak Encryption Algorithm",
                    Description = "Weak encryption algorithms detected",
                    Type = ComplianceRuleType.CryptographicPractices,
                    Pattern = @"(DES|3DES|RC4|MD5|SHA1)[\s\(]",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".php", ".cpp" },
                    RemediationGuidance = "Use strong encryption algorithms: AES-256, RSA-2048, SHA-256 or higher",
                    References = new List<string> { "PCI DSS v4.0 Requirement 3.6", "PCI DSS v4.0 Requirement 4.1" }
                }
            };

            // Requirement 4: Encrypt Transmission of Cardholder Data
            rules["data_transmission"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-4.1",
                    Name = "Insecure Data Transmission",
                    Description = "Sensitive data transmitted without encryption",
                    Type = ComplianceRuleType.NetworkSecurity,
                    Pattern = @"(http://.*card|ftp://.*card|telnet://|ssl\s*=\s*false|tls\s*=\s*false)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".php", ".config", ".xml" },
                    RemediationGuidance = "Use HTTPS, SFTP, or other secure protocols for transmitting cardholder data",
                    References = new List<string> { "PCI DSS v4.0 Requirement 4.1", "PCI DSS v4.0 Requirement 4.2" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-4.2",
                    Name = "Deprecated TLS Version",
                    Description = "Deprecated TLS/SSL versions in use",
                    Type = ComplianceRuleType.NetworkSecurity,
                    Pattern = @"(TLS\s*1\.0|TLS\s*1\.1|SSL\s*v?[123]|SSLv[123])",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".config", ".xml", ".properties" },
                    RemediationGuidance = "Use TLS 1.2 or higher for secure communications",
                    References = new List<string> { "PCI DSS v4.0 Requirement 4.2" }
                }
            };

            // Requirement 6: Develop and Maintain Secure Systems
            rules["secure_development"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-6.1",
                    Name = "SQL Injection Vulnerability",
                    Description = "SQL injection vulnerability detected",
                    Type = ComplianceRuleType.InputValidation,
                    Pattern = @"(string\s+\w+\s*=\s*[""'][^""']*[""']\s*\+\s*\w+|SqlCommand\([^)]*\+[^)]*\)|executeQuery\([^)]*\+[^)]*\))",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".php", ".js" },
                    RemediationGuidance = "Use parameterized queries or prepared statements to prevent SQL injection",
                    References = new List<string> { "PCI DSS v4.0 Requirement 6.2.4" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-6.2",
                    Name = "Cross-Site Scripting (XSS)",
                    Description = "Cross-site scripting vulnerability detected",
                    Type = ComplianceRuleType.OutputEncoding,
                    Pattern = @"(Response\.Write\([^)]*\+[^)]*\)|document\.write\([^)]*\+[^)]*\)|innerHTML\s*=\s*[^;]*\+|outerHTML\s*=\s*[^;]*\+)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".js", ".php", ".jsp", ".html" },
                    RemediationGuidance = "Encode output and validate input to prevent XSS attacks",
                    References = new List<string> { "PCI DSS v4.0 Requirement 6.2.4" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-6.3",
                    Name = "Hardcoded Secrets",
                    Description = "Hardcoded passwords or secrets detected",
                    Type = ComplianceRuleType.Authentication,
                    Pattern = @"(password\s*[:=]\s*[""'][^""']{3,}[""']|secret\s*[:=]\s*[""'][^""']{10,}[""']|api[_-]?key\s*[:=]\s*[""'][^""']{10,}[""'])",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".php", ".config", ".properties" },
                    RemediationGuidance = "Store secrets in secure configuration management or key vault systems",
                    References = new List<string> { "PCI DSS v4.0 Requirement 6.2.4" }
                }
            };

            // Requirement 7: Restrict Access by Business Need-to-Know
            rules["access_control"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-7.1",
                    Name = "Missing Authorization Check",
                    Description = "API endpoint accessing cardholder data without authorization",
                    Type = ComplianceRuleType.AccessControl,
                    Pattern = @"(\[Route\(.*card.*\)\]|\[HttpGet\(.*card.*\)\]|\[HttpPost\(.*card.*\)\])(?!.*\[Authorize\])",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java" },
                    RemediationGuidance = "Add authorization attributes to endpoints that access cardholder data",
                    References = new List<string> { "PCI DSS v4.0 Requirement 7.1" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-7.2",
                    Name = "Direct Object Reference",
                    Description = "Direct object reference without access control",
                    Type = ComplianceRuleType.AccessControl,
                    Pattern = @"(\/\{id\}|\/\{cardId\}|\/\{userId\})(?!.*authorization|.*permission)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".js" },
                    RemediationGuidance = "Implement proper authorization checks for direct object references",
                    References = new List<string> { "PCI DSS v4.0 Requirement 7.1" }
                }
            };

            // Requirement 8: Identify and Authenticate Access
            rules["authentication"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-8.1",
                    Name = "Weak Password Policy",
                    Description = "Weak password policy or validation detected",
                    Type = ComplianceRuleType.Authentication,
                    Pattern = @"(password\.length\s*[<>=]\s*[1-7]\b|minLength[""']?\s*:\s*[1-7]\b)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".js", ".py" },
                    RemediationGuidance = "Implement strong password policies (minimum 8 characters, complexity requirements)",
                    References = new List<string> { "PCI DSS v4.0 Requirement 8.3.6" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-8.2",
                    Name = "Missing Multi-Factor Authentication",
                    Description = "Cardholder data access without multi-factor authentication",
                    Type = ComplianceRuleType.Authentication,
                    Pattern = @"(card.*access|payment.*process)(?!.*(mfa|2fa|multi.?factor|two.?factor))",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".js", ".py" },
                    RemediationGuidance = "Implement multi-factor authentication for cardholder data access",
                    References = new List<string> { "PCI DSS v4.0 Requirement 8.4.2" }
                }
            };

            // Requirement 10: Log and Monitor All Access
            rules["logging"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-10.1",
                    Name = "Missing Audit Logging",
                    Description = "Cardholder data access without audit logging",
                    Type = ComplianceRuleType.Logging,
                    Pattern = @"(card.*access|payment.*process)(?!.*(log|audit|trace))",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".js", ".py" },
                    RemediationGuidance = "Add comprehensive audit logging for all cardholder data access",
                    References = new List<string> { "PCI DSS v4.0 Requirement 10.2" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "PCI-10.2",
                    Name = "Sensitive Data in Logs",
                    Description = "Sensitive data logged in plain text",
                    Type = ComplianceRuleType.Logging,
                    Pattern = @"(log|Log|logger)\.(info|debug|trace|warn).*(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{15,16})",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".js", ".py", ".php" },
                    RemediationGuidance = "Never log sensitive data like credit card numbers. Use masking or tokenization.",
                    References = new List<string> { "PCI DSS v4.0 Requirement 3.3" }
                }
            };

            return rules;
        }

        private List<ComplianceRule> GetApplicableRules(string fileExtension)
        {
            var applicableRules = new List<ComplianceRule>();
            
            foreach (var ruleCategory in _complianceRules.Values)
            {
                foreach (var rule in ruleCategory)
                {
                    if (rule.FileExtensions.Contains(fileExtension, StringComparer.OrdinalIgnoreCase) || 
                        rule.FileExtensions.Count == 0)
                    {
                        applicableRules.Add(rule);
                    }
                }
            }
            
            return applicableRules;
        }

        private ComplianceViolation CreateViolation(ComplianceRule rule, ComplianceFile file, int lineNumber, string codeLine)
        {
            return new ComplianceViolation
            {
                Id = Guid.NewGuid(),
                RequirementId = rule.RuleId,
                RuleId = rule.RuleId,
                Title = rule.Name,
                Description = rule.Description,
                Severity = rule.Severity,
                Status = ComplianceStatus.Open,
                FilePath = file.Path,
                LineNumber = lineNumber,
                CodeSnippet = codeLine.Trim(),
                RemediationGuidance = rule.RemediationGuidance,
                References = rule.References,
                DetectedAt = DateTime.UtcNow,
                CreatedAt = DateTime.UtcNow,
                ModifiedAt = DateTime.UtcNow
            };
        }

        private async Task<List<ComplianceEvidence>> CollectEvidenceAsync(ComplianceFile file, CancellationToken cancellationToken)
        {
            var evidence = new List<ComplianceEvidence>();
            var content = await file.ReadContentAsync();

            // Evidence for encryption usage
            if (Regex.IsMatch(content, @"(AES|RSA|SHA-256|HTTPS)", RegexOptions.IgnoreCase))
            {
                evidence.Add(new ComplianceEvidence
                {
                    ControlId = "PCI-3",
                    EvidenceType = "Encryption Implementation",
                    Description = "Strong encryption algorithms detected in code",
                    IsCompliant = true,
                    FilePath = file.Path,
                    Details = new Dictionary<string, object>
                    {
                        ["EncryptionMethods"] = Regex.Matches(content, @"(AES|RSA|SHA-256|HTTPS)", RegexOptions.IgnoreCase)
                            .Cast<Match>()
                            .Select(m => m.Value)
                            .Distinct()
                            .ToList()
                    }
                });
            }

            // Evidence for input validation
            if (Regex.IsMatch(content, @"(validate|sanitize|encode)", RegexOptions.IgnoreCase))
            {
                evidence.Add(new ComplianceEvidence
                {
                    ControlId = "PCI-6",
                    EvidenceType = "Input Validation",
                    Description = "Input validation mechanisms detected",
                    IsCompliant = true,
                    FilePath = file.Path,
                    Details = new Dictionary<string, object>
                    {
                        ["ValidationMethods"] = Regex.Matches(content, @"(validate|sanitize|encode)", RegexOptions.IgnoreCase)
                            .Cast<Match>()
                            .Select(m => m.Value)
                            .Distinct()
                            .ToList()
                    }
                });
            }

            return evidence;
        }

        private ComplianceScore CalculateComplianceScore(List<ComplianceViolation> violations)
        {
            var totalRequirements = _complianceRules.Values.Sum(rules => rules.Count);
            var violationsByRule = violations.GroupBy(v => v.RuleId).Count();
            var passedRequirements = Math.Max(0, totalRequirements - violationsByRule);

            var violationsBySeverity = violations
                .GroupBy(v => v.Severity)
                .ToDictionary(g => g.Key, g => g.Count());

            var overallScore = totalRequirements > 0 ? (decimal)passedRequirements / totalRequirements * 100 : 100;

            return new ComplianceScore
            {
                OverallScore = overallScore,
                TotalRequirements = totalRequirements,
                PassedRequirements = passedRequirements,
                FailedRequirements = violationsByRule,
                ViolationsBySeverity = violationsBySeverity,
                CategoryScores = CalculateCategoryScores(violations)
            };
        }

        private Dictionary<string, decimal> CalculateCategoryScores(List<ComplianceViolation> violations)
        {
            var categoryScores = new Dictionary<string, decimal>();
            
            foreach (var category in _complianceRules.Keys)
            {
                var categoryRules = _complianceRules[category];
                var categoryViolations = violations.Count(v => 
                    categoryRules.Any(r => r.RuleId == v.RuleId));
                
                var categoryScore = categoryRules.Count > 0 
                    ? (decimal)(categoryRules.Count - categoryViolations) / categoryRules.Count * 100 
                    : 100;
                
                categoryScores[category] = Math.Max(0, categoryScore);
            }
            
            return categoryScores;
        }

        private ComplianceRecommendations GenerateRecommendations(List<ComplianceViolation> violations)
        {
            var recommendations = new ComplianceRecommendations();
            
            var criticalViolations = violations.Where(v => v.Severity == ComplianceSeverity.Critical).ToList();
            var highViolations = violations.Where(v => v.Severity == ComplianceSeverity.High).ToList();
            var mediumViolations = violations.Where(v => v.Severity == ComplianceSeverity.Medium).ToList();

            // High priority actions for critical violations
            if (criticalViolations.Any(v => v.RuleId.Contains("3.")))
            {
                recommendations.HighPriorityActions.Add("Immediately encrypt all stored cardholder data using AES-256 or stronger encryption");
            }
            
            if (criticalViolations.Any(v => v.RuleId.Contains("6.1")))
            {
                recommendations.HighPriorityActions.Add("Fix SQL injection vulnerabilities using parameterized queries");
            }

            if (criticalViolations.Any(v => v.RuleId.Contains("6.3")))
            {
                recommendations.HighPriorityActions.Add("Remove hardcoded secrets and implement secure configuration management");
            }

            // Medium priority actions
            if (highViolations.Any())
            {
                recommendations.MediumPriorityActions.Add("Implement comprehensive input validation and output encoding");
                recommendations.MediumPriorityActions.Add("Enable multi-factor authentication for cardholder data access");
                recommendations.MediumPriorityActions.Add("Add audit logging for all cardholder data operations");
            }

            // Low priority actions
            if (mediumViolations.Any())
            {
                recommendations.LowPriorityActions.Add("Strengthen password policies and requirements");
                recommendations.LowPriorityActions.Add("Review and update network security configurations");
            }

            // Best practices
            recommendations.BestPractices.AddRange(new[]
            {
                "Implement regular security code reviews",
                "Use automated security testing tools in CI/CD pipeline",
                "Provide secure coding training for development team",
                "Establish incident response procedures for security violations",
                "Regularly update and patch all system components"
            });

            recommendations.Summary = GenerateExecutiveSummary(violations);

            return recommendations;
        }

        private string GenerateExecutiveSummary(List<ComplianceViolation> violations)
        {
            var criticalCount = violations.Count(v => v.Severity == ComplianceSeverity.Critical);
            var highCount = violations.Count(v => v.Severity == ComplianceSeverity.High);
            var totalCount = violations.Count;

            if (totalCount == 0)
            {
                return "PCI DSS compliance scan completed successfully with no violations detected. The codebase demonstrates good security practices.";
            }

            if (criticalCount > 0)
            {
                return $"PCI DSS compliance scan identified {totalCount} violations including {criticalCount} critical issues that require immediate attention. " +
                       "Critical violations may expose cardholder data and must be resolved to maintain PCI DSS compliance.";
            }

            if (highCount > 0)
            {
                return $"PCI DSS compliance scan found {totalCount} violations including {highCount} high-severity issues. " +
                       "While no critical violations were detected, high-severity issues should be addressed promptly to maintain security posture.";
            }

            return $"PCI DSS compliance scan completed with {totalCount} low to medium severity violations. " +
                   "These issues should be addressed as part of ongoing security improvement efforts.";
        }
    }
}