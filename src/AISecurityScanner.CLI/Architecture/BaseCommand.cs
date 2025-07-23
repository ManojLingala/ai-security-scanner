using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;

namespace AISecurityScanner.CLI.Architecture
{
    public abstract class BaseCommand
    {
        protected IServiceProvider ServiceProvider { get; }
        public abstract CommandMetadata Metadata { get; }
        
        protected BaseCommand(IServiceProvider serviceProvider)
        {
            ServiceProvider = serviceProvider;
        }

        public abstract Command BuildCommand();

        protected T GetService<T>() where T : notnull
        {
            return ServiceProvider.GetRequiredService<T>();
        }

        protected async Task<bool> CheckAuthentication()
        {
            var authService = GetService<Services.AuthService>();
            
            if (!await authService.IsAuthenticatedAsync())
            {
                Console.WriteLine("❌ You are not authenticated.");
                Console.WriteLine("Run 'aiscan auth login' or 'aiscan /auth:login' to authenticate first.");
                return false;
            }
            
            return true;
        }

        protected void ShowProgress(string message, int current, int total)
        {
            var percentage = (int)((current / (double)total) * 100);
            var progressBar = new string('█', percentage / 5) + new string('░', 20 - percentage / 5);
            Console.Write($"\r{message} [{progressBar}] {percentage}% ({current}/{total})");
            
            if (current == total)
                Console.WriteLine();
        }

        protected void ShowSpinner(string message, CancellationToken cancellationToken)
        {
            var spinnerChars = new[] { '⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏' };
            var i = 0;
            
            Task.Run(async () =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    Console.Write($"\r{spinnerChars[i++ % spinnerChars.Length]} {message}");
                    await Task.Delay(100);
                }
                Console.Write("\r" + new string(' ', message.Length + 3) + "\r");
            });
        }
    }
}