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
    public class GDPRComplianceProvider : IComplianceProvider
    {
        private readonly ILogger<GDPRComplianceProvider> _logger;
        private readonly Dictionary<string, List<ComplianceRule>> _complianceRules;

        public ComplianceFrameworkType Framework => ComplianceFrameworkType.GDPR;
        public string Version => "2016/679";
        public string Name => "General Data Protection Regulation";

        public GDPRComplianceProvider(ILogger<GDPRComplianceProvider> logger)
        {
            _logger = logger;
            _complianceRules = InitializeGDPRRules();
        }

        public async Task<ComplianceScanResult> ScanAsync(ComplianceScanContext context, CancellationToken cancellationToken = default)
        {
            var startTime = DateTime.UtcNow;
            var violations = new List<ComplianceViolation>();
            var evidence = new List<ComplianceEvidence>();

            try
            {
                _logger.LogInformation("Starting GDPR compliance scan for {FileCount} files", context.Files.Count);

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

                _logger.LogInformation("GDPR scan completed. Found {ViolationCount} violations", violations.Count);
                return scanResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during GDPR compliance scan");
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

        private Dictionary<string, List<ComplianceRule>> InitializeGDPRRules()
        {
            var rules = new Dictionary<string, List<ComplianceRule>>();

            // Article 5: Principles relating to processing of personal data
            rules["data_processing_principles"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-5.1",
                    Name = "Personal Data Without Purpose Limitation",
                    Description = "Personal data collected without specific purpose declaration",
                    Type = ComplianceRuleType.DataClassification,
                    Pattern = @"(collect|gather|store).*(personal|user|customer).*data(?!.*purpose|.*reason)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".sql" },
                    RemediationGuidance = "Define and document specific purposes for personal data collection",
                    References = new List<string> { "GDPR Article 5(1)(b)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-5.2",
                    Name = "Data Minimization Violation",
                    Description = "Collecting excessive personal data beyond necessity",
                    Type = ComplianceRuleType.DataClassification,
                    Pattern = @"select\s+\*.*from.*(user|customer|person)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".sql" },
                    RemediationGuidance = "Only collect personal data that is necessary for the specified purpose",
                    References = new List<string> { "GDPR Article 5(1)(c)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-5.3",
                    Name = "Missing Data Retention Period",
                    Description = "Personal data stored without retention period definition",
                    Type = ComplianceRuleType.DataRetention,
                    Pattern = @"(store|save|persist).*(personal|user|customer).*data(?!.*retention|.*expire|.*ttl)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement data retention periods and automatic deletion",
                    References = new List<string> { "GDPR Article 5(1)(e)" }
                }
            };

            // Article 6 & 7: Lawfulness and Consent
            rules["consent_management"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-6.1",
                    Name = "Processing Without Consent Check",
                    Description = "Personal data processing without verifying consent",
                    Type = ComplianceRuleType.Authorization,
                    Pattern = @"(process|handle|use).*(personal|user).*data(?!.*consent|.*permission)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Verify user consent before processing personal data",
                    References = new List<string> { "GDPR Article 6", "GDPR Article 7" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-7.1",
                    Name = "Missing Consent Withdrawal Mechanism",
                    Description = "No mechanism to withdraw consent",
                    Type = ComplianceRuleType.Configuration,
                    Pattern = @"consent(?!.*withdraw|.*revoke|.*cancel)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement easy consent withdrawal functionality",
                    References = new List<string> { "GDPR Article 7(3)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-7.2",
                    Name = "Pre-checked Consent Boxes",
                    Description = "Consent checkboxes pre-checked by default",
                    Type = ComplianceRuleType.CodePattern,
                    Pattern = @"(checkbox|consent).*checked\s*=\s*(true|""true"")",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".js", ".jsx", ".tsx", ".html" },
                    RemediationGuidance = "Consent must be freely given - remove pre-checked boxes",
                    References = new List<string> { "GDPR Article 7(2)" }
                }
            };

            // Articles 12-22: Rights of the data subject
            rules["data_subject_rights"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-15.1",
                    Name = "Missing Data Access Rights",
                    Description = "No functionality for users to access their data",
                    Type = ComplianceRuleType.AccessControl,
                    Pattern = @"(user|customer).*data(?!.*access|.*export|.*download)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement data subject access request (DSAR) functionality",
                    References = new List<string> { "GDPR Article 15" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-16.1",
                    Name = "Missing Data Rectification",
                    Description = "No mechanism for users to correct their data",
                    Type = ComplianceRuleType.Configuration,
                    Pattern = @"(profile|account|user)(?!.*edit|.*update|.*modify)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement user data rectification functionality",
                    References = new List<string> { "GDPR Article 16" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-17.1",
                    Name = "Missing Right to Erasure",
                    Description = "No functionality for data deletion (right to be forgotten)",
                    Type = ComplianceRuleType.DataRetention,
                    Pattern = @"(user|account)(?!.*delete|.*erase|.*remove)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement right to erasure functionality",
                    References = new List<string> { "GDPR Article 17" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-20.1",
                    Name = "Missing Data Portability",
                    Description = "No functionality for data portability",
                    Type = ComplianceRuleType.Configuration,
                    Pattern = @"export.*data(?!.*json|.*csv|.*xml)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement data export in machine-readable format",
                    References = new List<string> { "GDPR Article 20" }
                }
            };

            // Article 25: Data protection by design and by default
            rules["privacy_by_design"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-25.1",
                    Name = "Default Data Exposure",
                    Description = "Personal data exposed by default without privacy settings",
                    Type = ComplianceRuleType.Configuration,
                    Pattern = @"(privacy|visibility).*default.*public",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".config" },
                    RemediationGuidance = "Implement privacy by default - restrict data access by default",
                    References = new List<string> { "GDPR Article 25" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-25.2",
                    Name = "Missing Pseudonymization",
                    Description = "Personal data stored without pseudonymization",
                    Type = ComplianceRuleType.EncryptionCheck,
                    Pattern = @"(store|save).*(email|name|phone|address)(?!.*hash|.*encrypt|.*pseudonym)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement pseudonymization for personal data",
                    References = new List<string> { "GDPR Article 25", "GDPR Article 32" }
                }
            };

            // Article 32: Security of processing
            rules["security_measures"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-32.1",
                    Name = "Unencrypted Personal Data",
                    Description = "Personal data transmitted or stored without encryption",
                    Type = ComplianceRuleType.EncryptionCheck,
                    Pattern = @"(personal|user|customer).*data(?!.*encrypt|.*tls|.*https)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".config" },
                    RemediationGuidance = "Encrypt personal data in transit and at rest",
                    References = new List<string> { "GDPR Article 32(1)(a)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-32.2",
                    Name = "Weak Authentication for Personal Data Access",
                    Description = "Weak authentication mechanisms for accessing personal data",
                    Type = ComplianceRuleType.Authentication,
                    Pattern = @"(login|auth).*(password)(?!.*bcrypt|.*argon|.*pbkdf)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Use strong password hashing algorithms",
                    References = new List<string> { "GDPR Article 32" }
                }
            };

            // Article 33 & 34: Breach notification
            rules["breach_notification"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-33.1",
                    Name = "Missing Breach Detection",
                    Description = "No breach detection or notification mechanism",
                    Type = ComplianceRuleType.Logging,
                    Pattern = @"(security|breach|incident)(?!.*detect|.*notify|.*alert)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement breach detection and 72-hour notification process",
                    References = new List<string> { "GDPR Article 33" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-34.1",
                    Name = "Missing User Breach Notification",
                    Description = "No mechanism to notify users of data breaches",
                    Type = ComplianceRuleType.Configuration,
                    Pattern = @"breach(?!.*user.*notif|.*customer.*alert)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement user breach notification system",
                    References = new List<string> { "GDPR Article 34" }
                }
            };

            // Article 35: Data protection impact assessment
            rules["privacy_impact"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-35.1",
                    Name = "High-Risk Processing Without DPIA",
                    Description = "High-risk data processing without impact assessment",
                    Type = ComplianceRuleType.Administrative,
                    Pattern = @"(biometric|genetic|health|criminal|children).*data",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Conduct Data Protection Impact Assessment for high-risk processing",
                    References = new List<string> { "GDPR Article 35" }
                }
            };

            // Personal Data Patterns
            rules["personal_data_detection"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-PII.1",
                    Name = "Email Address Pattern",
                    Description = "Email addresses found in code",
                    Type = ComplianceRuleType.DataClassification,
                    Pattern = @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".sql", ".txt", ".log" },
                    RemediationGuidance = "Remove or encrypt email addresses in code",
                    References = new List<string> { "GDPR Article 32" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-PII.2",
                    Name = "Phone Number Pattern",
                    Description = "Phone numbers detected in code",
                    Type = ComplianceRuleType.DataClassification,
                    Pattern = @"(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".sql", ".txt" },
                    RemediationGuidance = "Remove or encrypt phone numbers in code",
                    References = new List<string> { "GDPR Article 32" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "GDPR-PII.3",
                    Name = "IP Address Logging",
                    Description = "IP addresses logged without anonymization",
                    Type = ComplianceRuleType.Logging,
                    Pattern = @"log.*ip(?!.*anonym|.*mask|.*hash)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Anonymize IP addresses in logs",
                    References = new List<string> { "GDPR Article 32" }
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

            // Evidence for consent management
            if (Regex.IsMatch(content, @"(consent|permission|opt-in)", RegexOptions.IgnoreCase))
            {
                evidence.Add(new ComplianceEvidence
                {
                    ControlId = "GDPR-6",
                    EvidenceType = "Consent Management",
                    Description = "Consent management mechanisms detected",
                    IsCompliant = true,
                    FilePath = file.Path,
                    Details = new Dictionary<string, object>
                    {
                        ["ConsentMethods"] = "Consent handling implemented"
                    }
                });
            }

            // Evidence for data subject rights
            if (Regex.IsMatch(content, @"(export|download|delete).*user.*data", RegexOptions.IgnoreCase))
            {
                evidence.Add(new ComplianceEvidence
                {
                    ControlId = "GDPR-15-20",
                    EvidenceType = "Data Subject Rights",
                    Description = "Data subject rights functionality detected",
                    IsCompliant = true,
                    FilePath = file.Path,
                    Details = new Dictionary<string, object>
                    {
                        ["Rights"] = "User data rights implemented"
                    }
                });
            }

            // Evidence for encryption
            if (Regex.IsMatch(content, @"(encrypt|aes|rsa|tls|https)", RegexOptions.IgnoreCase))
            {
                evidence.Add(new ComplianceEvidence
                {
                    ControlId = "GDPR-32",
                    EvidenceType = "Security Measures",
                    Description = "Data encryption mechanisms detected",
                    IsCompliant = true,
                    FilePath = file.Path,
                    Details = new Dictionary<string, object>
                    {
                        ["Security"] = "Encryption implemented for personal data"
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
            if (criticalViolations.Any(v => v.RuleId.Contains("6.1")))
            {
                recommendations.HighPriorityActions.Add("Implement consent verification for all personal data processing");
            }
            
            if (criticalViolations.Any(v => v.RuleId.Contains("17.1")))
            {
                recommendations.HighPriorityActions.Add("Implement right to erasure (right to be forgotten) functionality");
            }

            if (criticalViolations.Any(v => v.RuleId.Contains("32.1")))
            {
                recommendations.HighPriorityActions.Add("Encrypt all personal data in transit and at rest");
            }

            // High priority actions
            if (highViolations.Any())
            {
                recommendations.MediumPriorityActions.Add("Implement data subject access request (DSAR) procedures");
                recommendations.MediumPriorityActions.Add("Add consent withdrawal mechanisms");
                recommendations.MediumPriorityActions.Add("Implement breach notification procedures (72-hour rule)");
                recommendations.MediumPriorityActions.Add("Define and enforce data retention periods");
            }

            // Medium priority actions
            if (mediumViolations.Any())
            {
                recommendations.LowPriorityActions.Add("Implement data portability in machine-readable formats");
                recommendations.LowPriorityActions.Add("Add pseudonymization for personal data");
                recommendations.LowPriorityActions.Add("Anonymize IP addresses in logs");
                recommendations.LowPriorityActions.Add("Remove personal data from code and configuration files");
            }

            // Best practices
            recommendations.BestPractices.AddRange(new[]
            {
                "Conduct regular Data Protection Impact Assessments (DPIA)",
                "Maintain Records of Processing Activities (ROPA)",
                "Provide clear and transparent privacy notices",
                "Implement privacy by design and by default principles",
                "Train staff on GDPR compliance and data protection",
                "Appoint a Data Protection Officer (DPO) if required",
                "Review and update data processing agreements with third parties",
                "Implement data minimization principles",
                "Regularly test and evaluate security measures"
            });

            recommendations.Summary = GenerateExecutiveSummary(violations);

            return recommendations;
        }

        private string GenerateExecutiveSummary(List<ComplianceViolation> violations)
        {
            var criticalCount = violations.Count(v => v.Severity == ComplianceSeverity.Critical);
            var highCount = violations.Count(v => v.Severity == ComplianceSeverity.High);
            var totalCount = violations.Count;

            var consentViolations = violations.Count(v => v.RuleId.Contains("6.") || v.RuleId.Contains("7."));
            var rightsViolations = violations.Count(v => v.RuleId.StartsWith("GDPR-1") || v.RuleId.StartsWith("GDPR-2"));

            if (totalCount == 0)
            {
                return "GDPR compliance scan completed successfully with no violations detected. " +
                       "The codebase demonstrates good privacy protection practices.";
            }

            if (consentViolations > 0)
            {
                return $"GDPR compliance scan identified {totalCount} violations including {consentViolations} consent-related issues. " +
                       "Valid consent is fundamental to GDPR compliance and must be addressed immediately.";
            }

            if (criticalCount > 0)
            {
                return $"GDPR compliance scan identified {totalCount} violations including {criticalCount} critical issues. " +
                       "Critical violations pose significant privacy risks and potential regulatory penalties up to 4% of annual global turnover.";
            }

            if (highCount > 0)
            {
                return $"GDPR compliance scan found {totalCount} violations including {highCount} high-severity issues. " +
                       "These violations should be addressed promptly to ensure data subject rights and avoid regulatory action.";
            }

            return $"GDPR compliance scan completed with {totalCount} low to medium severity violations. " +
                   "Address these issues to strengthen privacy protection and maintain GDPR compliance.";
        }
    }
}