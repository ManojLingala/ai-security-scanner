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
    public class SOXComplianceProvider : IComplianceProvider
    {
        private readonly ILogger<SOXComplianceProvider> _logger;
        private readonly Dictionary<string, List<ComplianceRule>> _complianceRules;

        public ComplianceFrameworkType Framework => ComplianceFrameworkType.SOX;
        public string Version => "2002";
        public string Name => "Sarbanes-Oxley Act";

        public SOXComplianceProvider(ILogger<SOXComplianceProvider> logger)
        {
            _logger = logger;
            _complianceRules = InitializeSOXRules();
        }

        public async Task<ComplianceScanResult> ScanAsync(ComplianceScanContext context, CancellationToken cancellationToken = default)
        {
            var startTime = DateTime.UtcNow;
            var violations = new List<ComplianceViolation>();
            var evidence = new List<ComplianceEvidence>();

            try
            {
                _logger.LogInformation("Starting SOX compliance scan for {FileCount} files", context.Files.Count);

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

                _logger.LogInformation("SOX scan completed. Found {ViolationCount} violations", violations.Count);
                return scanResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during SOX compliance scan");
                throw;
            }
        }

        private async Task<List<ComplianceViolation>> ScanFileAsync(ComplianceFile file, CancellationToken cancellationToken)
        {
            var violations = new List<ComplianceViolation>();
            var content = await file.ReadContentAsync();
            var lines = content.Split('\n');

            var applicableRules = GetApplicableRules(file.Extension);

            for (int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
            {
                var line = lines[lineIndex];
                
                foreach (var rule in applicableRules)
                {
                    if (IsViolation(line, rule))
                    {
                        var violation = CreateViolation(rule, file, lineIndex + 1, line);
                        violations.Add(violation);
                    }
                }
            }

            return violations;
        }

        private Dictionary<string, List<ComplianceRule>> InitializeSOXRules()
        {
            var rules = new Dictionary<string, List<ComplianceRule>>();

            // Section 302: Corporate Responsibility for Financial Reports
            rules["financial_reporting"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-302.1",
                    Name = "Inadequate Financial Data Validation",
                    Description = "Financial calculations without proper validation",
                    Type = ComplianceRuleType.InputValidation,
                    Pattern = @"(revenue|profit|loss|income|expense|financial).*calculate(?!.*validate|.*verify)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".sql" },
                    RemediationGuidance = "Implement validation controls for all financial calculations",
                    References = new List<string> { "SOX Section 302" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-302.2",
                    Name = "Missing Financial Data Audit Trail",
                    Description = "Financial data modifications without audit logging",
                    Type = ComplianceRuleType.AuditLog,
                    Pattern = @"(financial|accounting|revenue|expense).*(update|modify|delete)(?!.*audit|.*log)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".sql" },
                    RemediationGuidance = "Implement comprehensive audit logging for financial data changes",
                    References = new List<string> { "SOX Section 302", "SOX Section 404" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-302.3",
                    Name = "Unencrypted Financial Data",
                    Description = "Financial data stored or transmitted without encryption",
                    Type = ComplianceRuleType.EncryptionCheck,
                    Pattern = @"(financial|accounting|revenue|ssn|ein|tax)(?!.*encrypt|.*hash)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".config" },
                    RemediationGuidance = "Encrypt all financial data at rest and in transit",
                    References = new List<string> { "SOX Section 302" }
                }
            };

            // Section 404: Management Assessment of Internal Controls
            rules["internal_controls"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-404.1",
                    Name = "Inadequate Segregation of Duties",
                    Description = "Single user can perform multiple critical financial operations",
                    Type = ComplianceRuleType.AccessControl,
                    Pattern = @"(approve|authorize|process).*(payment|transaction|transfer)(?!.*role|.*permission)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement role-based access control with proper segregation of duties",
                    References = new List<string> { "SOX Section 404" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-404.2",
                    Name = "Missing Transaction Approval Workflow",
                    Description = "Financial transactions processed without approval workflow",
                    Type = ComplianceRuleType.Authorization,
                    Pattern = @"(transaction|payment|transfer).*process(?!.*approval|.*authorize)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement approval workflows for financial transactions",
                    References = new List<string> { "SOX Section 404" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-404.3",
                    Name = "Weak Password Policy for Financial Systems",
                    Description = "Financial system access with weak password requirements",
                    Type = ComplianceRuleType.Authentication,
                    Pattern = @"(financial|accounting|treasury).*(password|auth)(?!.*strong|.*complex)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".config", ".properties" },
                    RemediationGuidance = "Enforce strong password policies for financial system access",
                    References = new List<string> { "SOX Section 404" }
                }
            };

            // Section 409: Real-Time Disclosure
            rules["disclosure_controls"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-409.1",
                    Name = "Delayed Financial Reporting",
                    Description = "Financial events not reported in real-time",
                    Type = ComplianceRuleType.Logging,
                    Pattern = @"(material|significant|financial).*event(?!.*realtime|.*immediate|.*notify)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement real-time reporting for material financial events",
                    References = new List<string> { "SOX Section 409" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-409.2",
                    Name = "Missing Event Notification System",
                    Description = "No automated notification for significant events",
                    Type = ComplianceRuleType.Configuration,
                    Pattern = @"(financial|material).*change(?!.*notify|.*alert|.*email)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement automated notifications for material changes",
                    References = new List<string> { "SOX Section 409" }
                }
            };

            // Section 802: Criminal Penalties for Document Alteration
            rules["document_retention"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-802.1",
                    Name = "Document Deletion Without Retention Check",
                    Description = "Financial documents deleted without retention policy check",
                    Type = ComplianceRuleType.DataRetention,
                    Pattern = @"(delete|remove|purge).*(document|record|file)(?!.*retention|.*policy)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".sql" },
                    RemediationGuidance = "Implement document retention policies before deletion",
                    References = new List<string> { "SOX Section 802" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-802.2",
                    Name = "Audit Record Modification",
                    Description = "Audit records can be modified or deleted",
                    Type = ComplianceRuleType.AuditLog,
                    Pattern = @"audit.*(update|modify|delete)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".sql" },
                    RemediationGuidance = "Make audit records immutable and tamper-proof",
                    References = new List<string> { "SOX Section 802" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-802.3",
                    Name = "Missing Document Versioning",
                    Description = "Financial documents without version control",
                    Type = ComplianceRuleType.DataRetention,
                    Pattern = @"(financial|accounting).*document(?!.*version|.*revision)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement document versioning for all financial records",
                    References = new List<string> { "SOX Section 802" }
                }
            };

            // Section 906: Corporate Responsibility for Financial Reports
            rules["executive_certification"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-906.1",
                    Name = "Missing Report Certification Process",
                    Description = "Financial reports without certification workflow",
                    Type = ComplianceRuleType.Authorization,
                    Pattern = @"(report|statement).*generate(?!.*certif|.*sign|.*approve)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement executive certification workflow for financial reports",
                    References = new List<string> { "SOX Section 906" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-906.2",
                    Name = "Weak Digital Signature Implementation",
                    Description = "Financial reports without secure digital signatures",
                    Type = ComplianceRuleType.CryptographicPractices,
                    Pattern = @"(sign|signature)(?!.*rsa|.*ecdsa|.*certificate)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Use cryptographically secure digital signatures",
                    References = new List<string> { "SOX Section 906" }
                }
            };

            // Financial Data Patterns
            rules["financial_data"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-FIN.1",
                    Name = "Hardcoded Financial Values",
                    Description = "Hardcoded financial amounts or rates in code",
                    Type = ComplianceRuleType.CodePattern,
                    Pattern = @"(rate|amount|price|fee)\s*=\s*\d+\.?\d*",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Move financial values to configuration with audit trail",
                    References = new List<string> { "SOX Section 404" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "SOX-FIN.2",
                    Name = "SQL Injection in Financial Queries",
                    Description = "SQL injection vulnerability in financial data queries",
                    Type = ComplianceRuleType.InputValidation,
                    Pattern = @"(financial|accounting|revenue).*sql.*\+\s*\w+",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".php" },
                    RemediationGuidance = "Use parameterized queries for all financial data access",
                    References = new List<string> { "SOX Section 404" }
                }
            };

            return rules;
        }

        private bool IsViolation(string line, ComplianceRule rule)
        {
            if (rule.IsRegex)
            {
                return Regex.IsMatch(line, rule.Pattern, RegexOptions.IgnoreCase);
            }
            return line.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase);
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

            // Evidence for financial controls
            if (Regex.IsMatch(content, @"(audit|log|track).*financial", RegexOptions.IgnoreCase))
            {
                evidence.Add(new ComplianceEvidence
                {
                    ControlId = "SOX-302",
                    EvidenceType = "Financial Audit Trail",
                    Description = "Financial audit logging mechanisms detected",
                    IsCompliant = true,
                    FilePath = file.Path,
                    Details = new Dictionary<string, object>
                    {
                        ["AuditMethods"] = "Financial transaction logging implemented"
                    }
                });
            }

            // Evidence for access controls
            if (Regex.IsMatch(content, @"(role|permission|authorize).*financial", RegexOptions.IgnoreCase))
            {
                evidence.Add(new ComplianceEvidence
                {
                    ControlId = "SOX-404",
                    EvidenceType = "Access Control",
                    Description = "Role-based access control for financial systems",
                    IsCompliant = true,
                    FilePath = file.Path,
                    Details = new Dictionary<string, object>
                    {
                        ["AccessControl"] = "RBAC implemented for financial operations"
                    }
                });
            }

            // Evidence for encryption
            if (Regex.IsMatch(content, @"(encrypt|hash|secure).*financial", RegexOptions.IgnoreCase))
            {
                evidence.Add(new ComplianceEvidence
                {
                    ControlId = "SOX-302",
                    EvidenceType = "Data Protection",
                    Description = "Financial data encryption detected",
                    IsCompliant = true,
                    FilePath = file.Path,
                    Details = new Dictionary<string, object>
                    {
                        ["Encryption"] = "Financial data protection implemented"
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

            // Critical actions
            if (criticalViolations.Any(v => v.RuleId.Contains("302")))
            {
                recommendations.HighPriorityActions.Add("Implement comprehensive financial data validation and audit trails");
            }
            
            if (criticalViolations.Any(v => v.RuleId.Contains("404")))
            {
                recommendations.HighPriorityActions.Add("Establish proper segregation of duties for financial operations");
            }

            if (criticalViolations.Any(v => v.RuleId.Contains("802")))
            {
                recommendations.HighPriorityActions.Add("Implement document retention policies and make audit records immutable");
            }

            // High priority actions
            if (highViolations.Any())
            {
                recommendations.MediumPriorityActions.Add("Strengthen authentication and authorization for financial systems");
                recommendations.MediumPriorityActions.Add("Implement real-time financial event reporting");
                recommendations.MediumPriorityActions.Add("Add digital signature capabilities for report certification");
            }

            // Medium priority actions
            if (mediumViolations.Any())
            {
                recommendations.LowPriorityActions.Add("Move hardcoded financial values to configuration");
                recommendations.LowPriorityActions.Add("Implement automated notification systems");
                recommendations.LowPriorityActions.Add("Enhance document versioning capabilities");
            }

            // Best practices
            recommendations.BestPractices.AddRange(new[]
            {
                "Conduct regular SOX compliance assessments",
                "Implement continuous monitoring of financial controls",
                "Provide SOX training to all personnel handling financial data",
                "Establish clear financial reporting procedures",
                "Maintain detailed documentation of all financial controls",
                "Perform regular internal audits of financial systems",
                "Implement fraud detection mechanisms"
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
                return "SOX compliance scan completed successfully with no violations detected. " +
                       "The codebase demonstrates strong financial controls and reporting mechanisms.";
            }

            if (criticalCount > 0)
            {
                return $"SOX compliance scan identified {totalCount} violations including {criticalCount} critical issues. " +
                       "Critical violations in financial controls must be addressed immediately to ensure accurate financial reporting and prevent fraud.";
            }

            if (highCount > 0)
            {
                return $"SOX compliance scan found {totalCount} violations including {highCount} high-severity issues. " +
                       "These violations should be addressed promptly to strengthen internal controls over financial reporting.";
            }

            return $"SOX compliance scan completed with {totalCount} low to medium severity violations. " +
                   "Address these issues to enhance the overall financial control environment.";
        }
    }
}