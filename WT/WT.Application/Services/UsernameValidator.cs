using System.Text.RegularExpressions;

namespace WT.Application.Services
{
    /// <summary>
    /// Validates usernames against offensive words and profanity.
    /// Uses the LDNOOBW (List of Dirty, Naughty, Obscene, and Otherwise Bad Words) list.
    /// </summary>
    public interface IUsernameValidator
    {
        /// <summary>
        /// Validates if username contains offensive words.
        /// </summary>
        /// <param name="username">Username to validate</param>
        /// <returns>True if username is acceptable, false if it contains bad words</returns>
        bool IsUsernameAllowed(string username);

        /// <summary>
        /// Gets the reason why username was rejected (if applicable).
        /// </summary>
        string? GetRejectionReason(string username);
    }

    public class UsernameValidator : IUsernameValidator
    {
        private readonly HashSet<string> _badWords;
        private static readonly Regex UsernameRegex = new(@"^[a-zA-Z0-9_.-]+$", RegexOptions.Compiled);
        private const int MinLength = 3;
        private const int MaxLength = 20;

        public UsernameValidator()
        {
            _badWords = LoadBadWords();
        }

        public bool IsUsernameAllowed(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            // Check length
            if (username.Length < MinLength || username.Length > MaxLength)
                return false;

            // Check format (alphanumeric, underscore, dash, dot only)
            if (!UsernameRegex.IsMatch(username))
                return false;

            // Check for offensive words (case-insensitive)
            var lowerUsername = username.ToLowerInvariant();
            
            // Check if username exactly matches a bad word
            if (_badWords.Contains(lowerUsername))
                return false;

            // Check if username contains bad words as substrings
            foreach (var badWord in _badWords)
            {
                if (lowerUsername.Contains(badWord))
                    return false;
            }

            return true;
        }

        public string? GetRejectionReason(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return "Username is required";

            if (username.Length < MinLength)
                return $"Username must be at least {MinLength} characters";

            if (username.Length > MaxLength)
                return $"Username must not exceed {MaxLength} characters";

            if (!UsernameRegex.IsMatch(username))
                return "Username can only contain letters, numbers, underscores, dashes, and dots";

            var lowerUsername = username.ToLowerInvariant();

            if (_badWords.Contains(lowerUsername) || _badWords.Any(w => lowerUsername.Contains(w)))
                return "Username contains inappropriate content";

            return null; // Username is valid
        }

        private static HashSet<string> LoadBadWords()
        {
            try
            {
                // Option 1: Load from embedded resource
                var assembly = typeof(UsernameValidator).Assembly;
                var resourceName = "WT.Application.Data.BadWords.en.txt";

                using var stream = assembly.GetManifestResourceStream(resourceName);
                if (stream == null)
                {
                    Console.WriteLine($"⚠️ Warning: Bad words list not found at {resourceName}. Username profanity filter disabled.");
                    return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                }

                using var reader = new StreamReader(stream);
                var words = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                string? line;
                while ((line = reader.ReadLine()) != null)
                {
                    var word = line.Trim().ToLowerInvariant();
                    if (!string.IsNullOrWhiteSpace(word))
                    {
                        words.Add(word);
                    }
                }

                Console.WriteLine($"✅ Loaded {words.Count} bad words for username validation");
                return words;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error loading bad words list: {ex.Message}");
                return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }
        }
    }
}
