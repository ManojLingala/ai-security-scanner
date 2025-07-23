namespace AISecurityScanner.CLI.Architecture
{
    public class CommandMetadata
    {
        public string Command { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Purpose { get; set; } = string.Empty;
        public bool WaveEnabled { get; set; }
        public PerformanceProfile PerformanceProfile { get; set; } = PerformanceProfile.Standard;
        public string[] Aliases { get; set; } = Array.Empty<string>();
        public Dictionary<string, string> Examples { get; set; } = new();
    }

    public enum PerformanceProfile
    {
        Optimization,
        Standard,
        Complex
    }

    public class PerformanceSettings
    {
        public int ParallelWorkers { get; set; }
        public bool CacheEnabled { get; set; }
        public bool ShallowScan { get; set; }
        public bool DeepAnalysis { get; set; }
        public int TimeoutSeconds { get; set; }

        public static Dictionary<PerformanceProfile, PerformanceSettings> Profiles = new()
        {
            [PerformanceProfile.Optimization] = new PerformanceSettings
            {
                ParallelWorkers = 8,
                CacheEnabled = true,
                ShallowScan = true,
                DeepAnalysis = false,
                TimeoutSeconds = 30
            },
            [PerformanceProfile.Standard] = new PerformanceSettings
            {
                ParallelWorkers = 4,
                CacheEnabled = true,
                ShallowScan = false,
                DeepAnalysis = false,
                TimeoutSeconds = 120
            },
            [PerformanceProfile.Complex] = new PerformanceSettings
            {
                ParallelWorkers = 2,
                CacheEnabled = false,
                ShallowScan = false,
                DeepAnalysis = true,
                TimeoutSeconds = 300
            }
        };
    }
}