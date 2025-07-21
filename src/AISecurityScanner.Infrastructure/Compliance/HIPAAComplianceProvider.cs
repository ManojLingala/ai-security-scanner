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
    public class HIPAAComplianceProvider : IComplianceProvider
    {
        private readonly ILogger<HIPAAComplianceProvider> _logger;
        private readonly Dictionary<string, List<ComplianceRule>> _complianceRules;

        public ComplianceFrameworkType Framework => ComplianceFrameworkType.HIPAA;
        public string Version => "2013 Omnibus Rule";
        public string Name => "HIPAA Security Rule";

        public HIPAAComplianceProvider(ILogger<HIPAAComplianceProvider> logger)
        {
            _logger = logger;
            _complianceRules = InitializeHIPAARules();
        }

        public async Task<ComplianceScanResult> ScanAsync(ComplianceScanContext context, CancellationToken cancellationToken = default)
        {
            var startTime = DateTime.UtcNow;
            var violations = new List<ComplianceViolation>();
            var evidence = new List<ComplianceEvidence>();

            try
            {
                _logger.LogInformation("Starting HIPAA Security Rule compliance scan for {FileCount} files", context.Files.Count);

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

                _logger.LogInformation("HIPAA scan completed. Found {ViolationCount} violations", violations.Count);
                return scanResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during HIPAA compliance scan");
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

        private Dictionary<string, List<ComplianceRule>> InitializeHIPAARules()
        {
            var rules = new Dictionary<string, List<ComplianceRule>>();

            // Administrative Safeguards
            rules["administrative_safeguards"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-ADM-1",
                    Name = "Missing Security Officer Assignment",
                    Description = "Code should have designated security responsibility and access controls",
                    Type = ComplianceRuleType.Administrative,
                    Pattern = @"(admin|administrator|root).*password",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".config" },
                    RemediationGuidance = "Implement role-based access controls and designated security officer responsibilities",
                    References = new List<string> { "45 CFR § 164.308(a)(2)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-ADM-2",
                    Name = "Insufficient Access Management",
                    Description = "PHI access without proper user authorization controls",
                    Type = ComplianceRuleType.AccessControl,
                    Pattern = @"(patient|medical|health|phi).*access(?!.*authorization|.*permission|.*role)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement proper authorization checks for PHI access",
                    References = new List<string> { "45 CFR § 164.308(a)(4)" }
                }
            };

            // Technical Safeguards - Access Control
            rules["access_control"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-AC-1",
                    Name = "Unique User Identification Missing",
                    Description = "PHI access without unique user identification",
                    Type = ComplianceRuleType.AccessControl,
                    Pattern = @"(patient|medical|health|phi).*query(?!.*user|.*userid|.*username)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".sql" },
                    RemediationGuidance = "Ensure every PHI access is associated with a unique user identifier",
                    References = new List<string> { "45 CFR § 164.312(a)(2)(i)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-AC-2",
                    Name = "Missing Emergency Access Procedure",
                    Description = "No emergency access procedures for PHI systems",
                    Type = ComplianceRuleType.AccessControl,
                    Pattern = @"(emergency|urgent|critical).*access(?!.*procedure|.*protocol)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement emergency access procedures for critical PHI access",
                    References = new List<string> { "45 CFR § 164.312(a)(2)(ii)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-AC-3",
                    Name = "Missing Automatic Logoff",
                    Description = "PHI systems without automatic logoff mechanisms",
                    Type = ComplianceRuleType.SessionManagement,
                    Pattern = @"(session|login)(?!.*timeout|.*expire|.*logoff)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".js", ".config" },
                    RemediationGuidance = "Implement automatic session timeout for PHI systems",
                    References = new List<string> { "45 CFR § 164.312(a)(2)(iii)" }
                }
            };

            // Technical Safeguards - Audit Controls
            rules["audit_controls"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-AU-1",
                    Name = "Missing PHI Access Logging",
                    Description = "PHI access without comprehensive audit logging",
                    Type = ComplianceRuleType.AuditLog,
                    Pattern = @"(patient|medical|health|phi).*(select|update|insert|delete|access)(?!.*log|.*audit|.*track)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".sql" },
                    RemediationGuidance = "Implement comprehensive audit logging for all PHI access and modifications",
                    References = new List<string> { "45 CFR § 164.312(b)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-AU-2",
                    Name = "Insufficient Audit Log Detail",
                    Description = "Audit logs missing required details (user, time, action)",
                    Type = ComplianceRuleType.AuditLog,
                    Pattern = @"log\.(info|debug|trace)(?!.*user.*time.*action)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Ensure audit logs include user ID, timestamp, and action performed",
                    References = new List<string> { "45 CFR § 164.312(b)" }
                }
            };

            // Technical Safeguards - Integrity
            rules["integrity"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-IN-1",
                    Name = "PHI Integrity Violation",
                    Description = "PHI modification without integrity controls",
                    Type = ComplianceRuleType.DataRetention,
                    Pattern = @"(patient|medical|health|phi).*(update|modify|change)(?!.*validation|.*integrity|.*checksum)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".sql" },
                    RemediationGuidance = "Implement integrity controls to prevent unauthorized PHI modification",
                    References = new List<string> { "45 CFR § 164.312(c)(1)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-IN-2",
                    Name = "Missing Data Validation",
                    Description = "PHI data input without proper validation",
                    Type = ComplianceRuleType.InputValidation,
                    Pattern = @"(patient|medical|health|phi).*input(?!.*validate|.*sanitize|.*verify)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement input validation for all PHI data entry points",
                    References = new List<string> { "45 CFR § 164.312(c)(2)" }
                }
            };

            // Technical Safeguards - Person or Entity Authentication
            rules["authentication"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-PE-1",
                    Name = "Weak Authentication for PHI Access",
                    Description = "PHI systems with insufficient authentication mechanisms",
                    Type = ComplianceRuleType.Authentication,
                    Pattern = @"(patient|medical|health|phi).*access(?!.*authenticate|.*verify|.*credential)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement strong authentication for PHI system access",
                    References = new List<string> { "45 CFR § 164.312(d)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-PE-2",
                    Name = "Missing Multi-Factor Authentication",
                    Description = "PHI access without multi-factor authentication",
                    Type = ComplianceRuleType.Authentication,
                    Pattern = @"(patient|medical|health|phi).*login(?!.*mfa|.*2fa|.*multi.?factor)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Implement multi-factor authentication for PHI access",
                    References = new List<string> { "45 CFR § 164.312(d)" }
                }
            };

            // Technical Safeguards - Transmission Security
            rules["transmission_security"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-TS-1",
                    Name = "Unencrypted PHI Transmission",
                    Description = "PHI transmitted without encryption",
                    Type = ComplianceRuleType.NetworkSecurity,
                    Pattern = @"(patient|medical|health|phi).*(send|transmit|email)(?!.*encrypt|.*https|.*tls|.*ssl)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".config" },
                    RemediationGuidance = "Encrypt all PHI transmissions using TLS 1.2 or higher",
                    References = new List<string> { "45 CFR § 164.312(e)(1)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-TS-2",
                    Name = "Weak Encryption for PHI",
                    Description = "PHI encrypted with weak or deprecated algorithms",
                    Type = ComplianceRuleType.CryptographicPractices,
                    Pattern = @"(patient|medical|health|phi).*(DES|3DES|RC4|MD5|SHA1)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Use strong encryption algorithms (AES-256, RSA-2048, SHA-256 or higher)",
                    References = new List<string> { "45 CFR § 164.312(e)(2)(ii)" }
                }
            };

            // Data Classification and PHI Detection
            rules["phi_detection"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-PHI-1",
                    Name = "SSN in Source Code",
                    Description = "Social Security Number pattern detected in code",
                    Type = ComplianceRuleType.DataClassification,
                    Pattern = @"\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".sql", ".txt", ".log" },
                    RemediationGuidance = "Remove SSNs from source code. Use encryption and secure storage.",
                    References = new List<string> { "45 CFR § 164.514(b)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-PHI-2",
                    Name = "Medical Record Number Pattern",
                    Description = "Medical record number or patient ID pattern detected",
                    Type = ComplianceRuleType.DataClassification,
                    Pattern = @"(mrn|medical.?record|patient.?id|health.?id)[:=]\s*[""']?[A-Za-z0-9\-]{6,}[""']?",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".sql", ".txt", ".log" },
                    RemediationGuidance = "Remove medical identifiers from source code. Use tokenization for testing.",
                    References = new List<string> { "45 CFR § 164.514(b)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-PHI-3",
                    Name = "Date of Birth Pattern",
                    Description = "Date of birth pattern that could identify individuals",
                    Type = ComplianceRuleType.DataClassification,
                    Pattern = @"(dob|date.?of.?birth|birth.?date)[:=]\s*[""']?\d{1,2}[-/]\d{1,2}[-/]\d{4}[""']?",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".sql", ".txt" },
                    RemediationGuidance = "Remove or encrypt date of birth information in code and logs",
                    References = new List<string> { "45 CFR § 164.514(b)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-PHI-4",
                    Name = "Health Insurance Information",
                    Description = "Health insurance or plan information detected",
                    Type = ComplianceRuleType.DataClassification,
                    Pattern = @"(insurance|plan.?id|subscriber.?id|policy.?number)[:=]\s*[""']?[A-Za-z0-9\-]{6,}[""']?",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".sql" },
                    RemediationGuidance = "Encrypt health insurance identifiers and remove from logs",
                    References = new List<string> { "45 CFR § 164.514(b)" }
                }
            };

            // Physical Safeguards
            rules["physical_safeguards"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-PS-1",
                    Name = "Facility Access Without Controls",
                    Description = "Physical access to systems containing PHI without controls",
                    Type = ComplianceRuleType.AccessControl,
                    Pattern = @"(server|datacenter|facility).*access(?!.*badge|.*card|.*biometric)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".config" },
                    RemediationGuidance = "Implement physical access controls (badges, biometrics) for facilities",
                    References = new List<string> { "45 CFR § 164.310(a)(1)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-PS-2",
                    Name = "Workstation Security Missing",
                    Description = "Workstations accessing PHI without security measures",
                    Type = ComplianceRuleType.Configuration,
                    Pattern = @"(workstation|desktop|laptop)(?!.*lock|.*timeout|.*screensaver)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".config" },
                    RemediationGuidance = "Implement automatic workstation locking and physical security",
                    References = new List<string> { "45 CFR § 164.310(b)", "45 CFR § 164.310(c)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-PS-3",
                    Name = "Device and Media Controls Missing",
                    Description = "Removable media and devices without controls",
                    Type = ComplianceRuleType.Configuration,
                    Pattern = @"(usb|removable|media|backup)(?!.*encrypt|.*control|.*policy)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".config" },
                    RemediationGuidance = "Implement device and media controls, encryption for removable media",
                    References = new List<string> { "45 CFR § 164.310(d)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-PS-4",
                    Name = "Missing Equipment Disposal Procedures",
                    Description = "PHI-containing equipment disposal without sanitization",
                    Type = ComplianceRuleType.DataRetention,
                    Pattern = @"(dispose|decommission|retire).*equipment(?!.*wipe|.*sanitize|.*destroy)",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Critical,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js", ".md" },
                    RemediationGuidance = "Implement secure data destruction procedures for equipment disposal",
                    References = new List<string> { "45 CFR § 164.310(d)(2)(i)" }
                }
            };

            // Error Handling and Information Disclosure
            rules["information_disclosure"] = new List<ComplianceRule>
            {
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-ID-1",
                    Name = "PHI in Error Messages",
                    Description = "PHI potentially exposed in error messages",
                    Type = ComplianceRuleType.ErrorHandling,
                    Pattern = @"(exception|error|throw).*patient|medical|health|phi",
                    IsRegex = true,
                    Severity = ComplianceSeverity.High,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Sanitize error messages to prevent PHI disclosure",
                    References = new List<string> { "45 CFR § 164.312(a)(1)" }
                },
                new ComplianceRule
                {
                    Id = Guid.NewGuid(),
                    RuleId = "HIPAA-ID-2",
                    Name = "Debug Information Exposure",
                    Description = "Debug output may expose PHI",
                    Type = ComplianceRuleType.ErrorHandling,
                    Pattern = @"(debug|console|print).*patient|medical|health|phi",
                    IsRegex = true,
                    Severity = ComplianceSeverity.Medium,
                    FileExtensions = new List<string> { ".cs", ".java", ".py", ".js" },
                    RemediationGuidance = "Remove debug statements containing PHI from production code",
                    References = new List<string> { "45 CFR § 164.312(a)(1)" }
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

            // Evidence for encryption implementation
            if (Regex.IsMatch(content, @"(AES|RSA|SHA-256|TLS|HTTPS)", RegexOptions.IgnoreCase))
            {
                evidence.Add(new ComplianceEvidence
                {
                    ControlId = "HIPAA-TS",
                    EvidenceType = "Encryption Implementation",
                    Description = "Strong encryption algorithms detected for PHI protection",
                    IsCompliant = true,
                    FilePath = file.Path,
                    Details = new Dictionary<string, object>
                    {
                        ["EncryptionMethods"] = Regex.Matches(content, @"(AES|RSA|SHA-256|TLS|HTTPS)", RegexOptions.IgnoreCase)
                            .Cast<Match>()
                            .Select(m => m.Value)
                            .Distinct()
                            .ToList()
                    }
                });
            }

            // Evidence for audit logging
            if (Regex.IsMatch(content, @"(audit|log|track).*user.*action", RegexOptions.IgnoreCase))
            {
                evidence.Add(new ComplianceEvidence
                {
                    ControlId = "HIPAA-AU",
                    EvidenceType = "Audit Logging",
                    Description = "Audit logging mechanisms detected",
                    IsCompliant = true,
                    FilePath = file.Path,
                    Details = new Dictionary<string, object>
                    {
                        ["AuditMethods"] = "Comprehensive audit logging implemented"
                    }
                });
            }

            // Evidence for access controls
            if (Regex.IsMatch(content, @"(authorize|authenticate|permission)", RegexOptions.IgnoreCase))
            {
                evidence.Add(new ComplianceEvidence
                {
                    ControlId = "HIPAA-AC",
                    EvidenceType = "Access Control",
                    Description = "Access control mechanisms detected",
                    IsCompliant = true,
                    FilePath = file.Path,
                    Details = new Dictionary<string, object>
                    {
                        ["AccessControlMethods"] = Regex.Matches(content, @"(authorize|authenticate|permission)", RegexOptions.IgnoreCase)
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

            // Critical actions for PHI exposure
            if (criticalViolations.Any(v => v.RuleId.Contains("PHI")))
            {
                recommendations.HighPriorityActions.Add("Immediately remove or encrypt all PHI found in source code and logs");
            }
            
            if (criticalViolations.Any(v => v.RuleId.Contains("AU-1")))
            {
                recommendations.HighPriorityActions.Add("Implement comprehensive audit logging for all PHI access");
            }

            if (criticalViolations.Any(v => v.RuleId.Contains("TS-1")))
            {
                recommendations.HighPriorityActions.Add("Encrypt all PHI transmissions using TLS 1.2 or higher");
            }

            if (criticalViolations.Any(v => v.RuleId.Contains("PE-1")))
            {
                recommendations.HighPriorityActions.Add("Implement strong authentication for all PHI system access");
            }

            // High priority actions
            if (highViolations.Any())
            {
                recommendations.MediumPriorityActions.Add("Implement multi-factor authentication for PHI access");
                recommendations.MediumPriorityActions.Add("Add integrity controls for PHI modifications");
                recommendations.MediumPriorityActions.Add("Strengthen access control mechanisms");
                recommendations.MediumPriorityActions.Add("Implement proper error handling to prevent PHI disclosure");
            }

            // Medium priority actions
            if (mediumViolations.Any())
            {
                recommendations.LowPriorityActions.Add("Implement automatic session timeout mechanisms");
                recommendations.LowPriorityActions.Add("Add emergency access procedures");
                recommendations.LowPriorityActions.Add("Remove debug statements that may expose PHI");
            }

            // Best practices
            recommendations.BestPractices.AddRange(new[]
            {
                "Conduct regular HIPAA security risk assessments",
                "Provide HIPAA security training to all development staff",
                "Implement data minimization principles for PHI handling",
                "Establish incident response procedures for PHI breaches",
                "Use de-identification techniques for test data",
                "Implement regular access reviews and user provisioning",
                "Maintain business associate agreements for third-party services"
            });

            recommendations.Summary = GenerateExecutiveSummary(violations);

            return recommendations;
        }

        private string GenerateExecutiveSummary(List<ComplianceViolation> violations)
        {
            var criticalCount = violations.Count(v => v.Severity == ComplianceSeverity.Critical);
            var highCount = violations.Count(v => v.Severity == ComplianceSeverity.High);
            var totalCount = violations.Count;

            var phiViolations = violations.Count(v => v.RuleId.Contains("PHI"));

            if (totalCount == 0)
            {
                return "HIPAA Security Rule compliance scan completed successfully with no violations detected. " +
                       "The codebase demonstrates good PHI protection practices.";
            }

            if (phiViolations > 0)
            {
                return $"HIPAA compliance scan identified {totalCount} violations including {phiViolations} potential PHI exposures. " +
                       "PHI found in code or logs represents a critical compliance risk and must be addressed immediately to prevent HIPAA violations.";
            }

            if (criticalCount > 0)
            {
                return $"HIPAA compliance scan identified {totalCount} violations including {criticalCount} critical issues. " +
                       "Critical violations pose significant risk to PHI security and must be resolved to maintain HIPAA compliance.";
            }

            if (highCount > 0)
            {
                return $"HIPAA compliance scan found {totalCount} violations including {highCount} high-severity issues. " +
                       "While no critical violations were detected, high-severity issues should be addressed to strengthen PHI protection.";
            }

            return $"HIPAA compliance scan completed with {totalCount} low to medium severity violations. " +
                   "These issues should be addressed as part of ongoing PHI security improvement efforts.";
        }
    }
}