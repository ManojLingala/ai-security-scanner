namespace AISecurityScanner.Infrastructure.Configuration
{
    public class RavenDbConfiguration
    {
        public string[] Urls { get; set; } = Array.Empty<string>();
        public string Database { get; set; } = string.Empty;
        public string? CertificatePath { get; set; }
        public string? CertificatePassword { get; set; }
        public bool UseEmbedded { get; set; }
        public string? EmbeddedServerUrl { get; set; }
    }
}