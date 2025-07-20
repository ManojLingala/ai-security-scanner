using System;

namespace AISecurityScanner.Domain.ValueObjects
{
    public class PackageInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Ecosystem { get; set; } = string.Empty;
        public bool Exists { get; set; }
        public bool IsHallucinated { get; set; }
        public DateTime? LastChecked { get; set; }
        public string? RegistryUrl { get; set; }
    }
}