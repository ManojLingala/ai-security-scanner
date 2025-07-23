namespace AISecurityScanner.CLI.Architecture
{
    public class WaveOrchestrator
    {
        public class Wave
        {
            public string Name { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
            public Func<WaveContext, Task<WaveResult>> ExecuteAsync { get; set; } = _ => Task.FromResult(new WaveResult());
            public bool IsOptional { get; set; }
            public double ComplexityThreshold { get; set; } = 0.7;
        }

        public class WaveContext
        {
            public Dictionary<string, object> Data { get; set; } = new();
            public double ComplexityScore { get; set; }
            public int FileCount { get; set; }
            public List<string> SecurityIndicators { get; set; } = new();
            public CancellationToken CancellationToken { get; set; }
        }

        public class WaveResult
        {
            public bool Success { get; set; } = true;
            public Dictionary<string, object> OutputData { get; set; } = new();
            public List<string> Messages { get; set; } = new();
            public TimeSpan Duration { get; set; }
        }

        private readonly List<Wave> _waves = new();

        public WaveOrchestrator AddWave(Wave wave)
        {
            _waves.Add(wave);
            return this;
        }

        public async Task<Dictionary<string, WaveResult>> ExecuteAsync(WaveContext context)
        {
            var results = new Dictionary<string, WaveResult>();
            var shouldRunOptional = context.ComplexityScore >= 0.7 || context.FileCount > 20;

            Console.WriteLine($"🌊 Wave Orchestration Started (Complexity: {context.ComplexityScore:F2})");
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            foreach (var wave in _waves)
            {
                if (wave.IsOptional && !shouldRunOptional && context.ComplexityScore < wave.ComplexityThreshold)
                {
                    Console.WriteLine($"⏭️  Skipping {wave.Name} (below complexity threshold)");
                    continue;
                }

                Console.Write($"🔄 {wave.Name}: {wave.Description}... ");
                
                var startTime = DateTime.UtcNow;
                try
                {
                    var result = await wave.ExecuteAsync(context);
                    result.Duration = DateTime.UtcNow - startTime;
                    
                    results[wave.Name] = result;
                    
                    // Pass data to next wave
                    foreach (var kvp in result.OutputData)
                    {
                        context.Data[kvp.Key] = kvp.Value;
                    }

                    if (result.Success)
                    {
                        Console.WriteLine($"✅ ({result.Duration.TotalSeconds:F1}s)");
                        foreach (var message in result.Messages)
                        {
                            Console.WriteLine($"   • {message}");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"⚠️  Warning: {string.Join(", ", result.Messages)}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Failed: {ex.Message}");
                    results[wave.Name] = new WaveResult 
                    { 
                        Success = false, 
                        Messages = { ex.Message },
                        Duration = DateTime.UtcNow - startTime
                    };
                }

                if (context.CancellationToken.IsCancellationRequested)
                {
                    Console.WriteLine("🛑 Wave execution cancelled");
                    break;
                }
            }

            Console.WriteLine();
            Console.WriteLine($"📊 Wave Summary: {results.Count(r => r.Value.Success)}/{_waves.Count} waves completed successfully");
            Console.WriteLine($"⏱️  Total duration: {results.Sum(r => r.Value.Duration.TotalSeconds):F1}s");

            return results;
        }

        public static double CalculateComplexity(string directoryPath)
        {
            var factors = new Dictionary<string, double>();
            
            // File count factor
            var fileCount = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories).Length;
            factors["FileCount"] = Math.Min(fileCount / 100.0, 1.0);
            
            // Language diversity factor
            var extensions = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories)
                .Select(f => Path.GetExtension(f).ToLower())
                .Distinct()
                .Count();
            factors["LanguageDiversity"] = Math.Min(extensions / 10.0, 1.0);
            
            // Security indicators
            var securityPatterns = new[] { "auth", "security", "crypto", "password", "token", "key", "certificate" };
            var hasSecurityFiles = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories)
                .Any(f => securityPatterns.Any(p => Path.GetFileName(f).ToLower().Contains(p)));
            factors["SecurityIndicators"] = hasSecurityFiles ? 0.8 : 0.2;
            
            // Calculate weighted average
            return factors.Values.Average();
        }
    }
}