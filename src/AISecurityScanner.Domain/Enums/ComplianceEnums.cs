namespace AISecurityScanner.Domain.Enums
{
    public enum ComplianceFrameworkType
    {
        PCI_DSS,
        HIPAA,
        SOX,
        GDPR,
        OWASP,
        NIST,
        ISO27001,
        SOC2,
        FedRAMP,
        CCPA
    }

    public enum ComplianceSeverity
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    public enum ComplianceStatus
    {
        Open,
        InProgress,
        Resolved,
        Accepted,
        FalsePositive,
        NotApplicable
    }

    public enum ComplianceRuleType
    {
        CodePattern,
        DataClassification,
        EncryptionCheck,
        AccessControl,
        AuditLog,
        Configuration,
        DataRetention,
        NetworkSecurity,
        Authentication,
        Authorization,
        InputValidation,
        OutputEncoding,
        SessionManagement,
        ErrorHandling,
        Logging,
        CryptographicPractices,
        Administrative
    }

    public enum ComplianceControlType
    {
        Administrative,
        Technical,
        Physical,
        Procedural,
        Preventive,
        Detective,
        Corrective,
        Compensating
    }

    public enum DataClassificationType
    {
        Public,
        Internal,
        Confidential,
        Restricted,
        PersonallyIdentifiableInformation,
        ProtectedHealthInformation,
        PaymentCardInformation,
        Sensitive,
        TopSecret
    }

    public enum EncryptionRequirement
    {
        None,
        InTransit,
        AtRest,
        Both,
        EndToEnd
    }

    public enum AuthenticationMethod
    {
        None,
        Basic,
        Token,
        Certificate,
        TwoFactor,
        MultiFactor,
        Biometric,
        SmartCard
    }

    public enum AuditLogLevel
    {
        None,
        Basic,
        Detailed,
        Comprehensive,
        Forensic
    }
}