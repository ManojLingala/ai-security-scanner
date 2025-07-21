using System;
using System.Data.SqlClient;
using System.Web;

namespace TestSample
{
    public class UserController
    {
        // SQL Injection vulnerability
        public string GetUser(string userId)
        {
            var connectionString = "Server=localhost;Database=Test;";
            using var connection = new SqlConnection(connectionString);
            var query = "SELECT * FROM Users WHERE Id = '" + userId + "'"; // Vulnerable
            using var command = new SqlCommand(query, connection);
            return command.ExecuteScalar()?.ToString();
        }

        // XSS vulnerability
        public string DisplayMessage(string userInput)
        {
            return "<div>" + userInput + "</div>"; // Vulnerable - no encoding
        }

        // Hardcoded secret
        private const string ApiKey = "sk-1234567890abcdef"; // Vulnerable

        // Insecure random number generation
        public int GenerateToken()
        {
            var random = new Random(); // Vulnerable - not cryptographically secure
            return random.Next();
        }

        // Missing input validation
        public void ProcessFile(string fileName)
        {
            var path = "/uploads/" + fileName; // Vulnerable to path traversal
            System.IO.File.ReadAllText(path);
        }
    }
}