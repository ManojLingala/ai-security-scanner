using System.Diagnostics;
using System.Text.RegularExpressions;

namespace AISecurityScanner.CLI.Services
{
    public class AuthService
    {
        private readonly ConfigService _configService;
        
        public AuthService(ConfigService configService)
        {
            _configService = configService;
        }

        public async Task<bool> LoginAsync()
        {
            Console.WriteLine("🔐 AI Security Scanner Authentication");
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Console.WriteLine();

            // Check if already authenticated
            if (await _configService.IsAuthenticatedAsync())
            {
                Console.WriteLine("✅ You are already authenticated!");
                Console.WriteLine();
                
                Console.Write("Do you want to re-authenticate? (y/N): ");
                var response = Console.ReadLine()?.Trim().ToLower();
                if (response != "y" && response != "yes")
                {
                    return true;
                }
                Console.WriteLine();
            }

            // Try to get token from Claude Code CLI if available
            var existingToken = await TryGetClaudeCodeTokenAsync();
            
            if (!string.IsNullOrEmpty(existingToken))
            {
                return await HandleExistingTokenAsync(existingToken);
            }
            else
            {
                return await HandleManualTokenEntryAsync();
            }
        }

        private async Task<string?> TryGetClaudeCodeTokenAsync()
        {
            try
            {
                Console.WriteLine("🔍 Checking for existing Claude Code authentication...");
                
                // Try to detect Claude Code CLI and get token
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "claude",
                        Arguments = "auth status --json",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                var error = await process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync();

                if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
                {
                    // Parse JSON response to extract token
                    // This is a simplified approach - in reality, you'd use proper JSON parsing
                    var tokenMatch = Regex.Match(output, @"""token"":\s*""([^""]+)""");
                    if (tokenMatch.Success)
                    {
                        return tokenMatch.Groups[1].Value;
                    }
                }
            }
            catch (Exception)
            {
                // Claude Code CLI not available or not authenticated
            }

            return null;
        }

        private async Task<bool> HandleExistingTokenAsync(string token)
        {
            Console.WriteLine("✅ Found existing Claude Code authentication!");
            Console.WriteLine();
            Console.WriteLine("🔒 PERMISSION REQUEST");
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━");
            Console.WriteLine();
            Console.WriteLine("The AI Security Scanner would like to:");
            Console.WriteLine("  • Access your Claude API token for security scanning");
            Console.WriteLine("  • Analyze code files for security vulnerabilities");
            Console.WriteLine("  • Generate compliance reports");
            Console.WriteLine("  • Store scan results locally");
            Console.WriteLine();
            Console.WriteLine("Your token will be stored securely in ~/.aiscan/config.json");
            Console.WriteLine("You can revoke access at any time with 'aiscan auth logout'");
            Console.WriteLine();

            while (true)
            {
                Console.Write("Do you consent to these permissions? (y/n): ");
                var consent = Console.ReadLine()?.Trim().ToLower();
                
                if (consent == "y" || consent == "yes")
                {
                    await _configService.SetClaudeTokenAsync(token);
                    await _configService.SetUserConsentAsync(true);
                    
                    Console.WriteLine();
                    Console.WriteLine("✅ Authentication successful!");
                    Console.WriteLine("🎉 You can now use AI Security Scanner CLI commands");
                    return true;
                }
                else if (consent == "n" || consent == "no")
                {
                    Console.WriteLine();
                    Console.WriteLine("❌ Permission denied. AI Security Scanner requires token access to function.");
                    return false;
                }
                else
                {
                    Console.WriteLine("Please enter 'y' for yes or 'n' for no.");
                }
            }
        }

        private async Task<bool> HandleManualTokenEntryAsync()
        {
            Console.WriteLine("❓ No existing Claude Code authentication found.");
            Console.WriteLine();
            Console.WriteLine("To use AI Security Scanner, you need a Claude API token.");
            Console.WriteLine();
            Console.WriteLine("📋 How to get your token:");
            Console.WriteLine("  1. Install Claude Code CLI: https://docs.anthropic.com/en/docs/claude-code");
            Console.WriteLine("  2. Run: claude auth login");
            Console.WriteLine("  3. Re-run: aiscan auth login");
            Console.WriteLine();
            Console.WriteLine("OR manually enter your Anthropic API key:");
            Console.WriteLine();

            Console.Write("Enter your Claude API token (or press Enter to skip): ");
            var token = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(token))
            {
                Console.WriteLine();
                Console.WriteLine("⚠️  No token provided. Please run 'aiscan auth login' after setting up Claude Code.");
                return false;
            }

            // Validate token format (basic validation)
            if (!token.StartsWith("sk-ant-") || token.Length < 20)
            {
                Console.WriteLine();
                Console.WriteLine("❌ Invalid token format. Claude API tokens start with 'sk-ant-'");
                return false;
            }

            // Request consent for manual token
            Console.WriteLine();
            Console.WriteLine("🔒 By providing your token, you consent to:");
            Console.WriteLine("  • AI Security Scanner storing your token locally");
            Console.WriteLine("  • Using the token for security scanning and analysis");
            Console.WriteLine("  • Local storage of scan results");
            Console.WriteLine();
            
            Console.Write("Proceed? (y/n): ");
            var consent = Console.ReadLine()?.Trim().ToLower();
            
            if (consent == "y" || consent == "yes")
            {
                await _configService.SetClaudeTokenAsync(token);
                await _configService.SetUserConsentAsync(true);
                
                Console.WriteLine();
                Console.WriteLine("✅ Token saved successfully!");
                Console.WriteLine("🎉 You can now use AI Security Scanner CLI commands");
                return true;
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("❌ Authentication cancelled.");
                return false;
            }
        }

        public async Task<bool> IsAuthenticatedAsync()
        {
            return await _configService.IsAuthenticatedAsync();
        }

        public async Task ShowStatusAsync()
        {
            var config = await _configService.GetConfigAsync();
            
            Console.WriteLine("🔐 Authentication Status");
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━");
            Console.WriteLine();
            
            if (await _configService.IsAuthenticatedAsync())
            {
                Console.WriteLine("Status: ✅ Authenticated");
                Console.WriteLine($"Token: {MaskToken(config.ClaudeToken)}");
                Console.WriteLine($"Last Login: {config.LastLogin?.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"Consent Given: {config.UserConsentGiven}");
            }
            else
            {
                Console.WriteLine("Status: ❌ Not Authenticated");
                Console.WriteLine();
                Console.WriteLine("Run 'aiscan auth login' to authenticate");
            }
        }

        public async Task LogoutAsync()
        {
            if (!await _configService.IsAuthenticatedAsync())
            {
                Console.WriteLine("❓ You are not currently authenticated.");
                return;
            }

            Console.Write("Are you sure you want to logout? (y/N): ");
            var response = Console.ReadLine()?.Trim().ToLower();
            
            if (response == "y" || response == "yes")
            {
                await _configService.LogoutAsync();
                Console.WriteLine("✅ Logged out successfully!");
                Console.WriteLine("Your stored tokens have been cleared.");
            }
            else
            {
                Console.WriteLine("❌ Logout cancelled.");
            }
        }

        private static string? MaskToken(string? token)
        {
            if (string.IsNullOrEmpty(token))
                return "Not set";
                
            if (token.Length <= 8)
                return "***";
                
            return $"{token[..4]}...{token[^4..]}";
        }
    }
}