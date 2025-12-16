using System.Reflection;
using System.Text.RegularExpressions;
using WT.Application.Contracts;

namespace WT.Infrastructure.Services
{
    /// <summary>
    /// Validates usernames against offensive words and profanity.
    /// Uses the LDNOOBW (List of Dirty, Naughty, Obscene, and Otherwise Bad Words) list.
    /// </summary>
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

            if (username.Length < MinLength || username.Length > MaxLength)
                return false;

            if (!UsernameRegex.IsMatch(username))
                return false;

            var lowerUsername = username.ToLowerInvariant();

            if (_badWords.Contains(lowerUsername))
                return false;

            foreach (var badWord in _badWords)
            {
                if (lowerUsername.Contains(badWord))
                    return false;
            }

            return true;
        }

        public Task<bool> IsUsernameValidAsync(string username)
        {
            return Task.FromResult(IsUsernameAllowed(username));
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

            return null;
        }

        private static HashSet<string> LoadBadWords()
        {
            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                
                Console.WriteLine($"🔍 Loading bad words from assembly: {assembly.FullName}");
                Console.WriteLine($"📂 Assembly location: {assembly.Location}");
                
                // ✅ List ALL embedded resources
                var resourceNames = assembly.GetManifestResourceNames();
                Console.WriteLine($"📋 Found {resourceNames.Length} embedded resource(s):");
                
                if (resourceNames.Length == 0)
                {
                    Console.WriteLine("   ⚠️ NO EMBEDDED RESOURCES FOUND!");
                }
                else
                {
                    foreach (var name in resourceNames)
                    {
                        Console.WriteLine($"   ✓ {name}");
                    }
                }

                // ✅ Try exact match first
                const string expectedResourceName = "WT.Infrastructure.Data.BadWords.en.txt";
                
                if (resourceNames.Contains(expectedResourceName))
                {
                    Console.WriteLine($"✅ Found exact match: {expectedResourceName}");
                    using var stream = assembly.GetManifestResourceStream(expectedResourceName);
                    if (stream != null)
                    {
                        return ReadWordsFromStream(stream, $"embedded: {expectedResourceName}");
                    }
                    else
                    {
                        Console.WriteLine($"❌ ERROR: Stream was null for {expectedResourceName}");
                    }
                }

                // ✅ Try partial match
                var foundResourceName = resourceNames.FirstOrDefault(r => r.EndsWith("BadWords.en.txt"));
                if (foundResourceName != null)
                {
                    Console.WriteLine($"✅ Found partial match: {foundResourceName}");
                    using var stream = assembly.GetManifestResourceStream(foundResourceName);
                    if (stream != null)
                    {
                        return ReadWordsFromStream(stream, $"embedded: {foundResourceName}");
                    }
                }

                // ✅ FALLBACK to file system (keep your existing fallback code)
                Console.WriteLine("⚠️ Embedded resource not found, trying file system...");
                
                var assemblyLocation = Path.GetDirectoryName(assembly.Location) ?? string.Empty;
                var currentDirectory = Directory.GetCurrentDirectory();
                
                // Try multiple possible paths
                var possiblePaths = new[]
                {
                    // Path relative to assembly location
                    Path.Combine(assemblyLocation, "Data", "BadWords.en.txt"),
                    
                    // Path relative to project root (during development)
                    Path.Combine(currentDirectory, "WT.Infrastructure", "Data", "BadWords.en.txt"),
                    Path.Combine(currentDirectory, "..", "WT.Infrastructure", "Data", "BadWords.en.txt"),
                    Path.Combine(currentDirectory, "..", "..", "WT.Infrastructure", "Data", "BadWords.en.txt"),
                    
                    // Path in the working directory
                    Path.Combine(currentDirectory, "Data", "BadWords.en.txt"),
                    
                    // Navigate up from bin/Debug/net9.0
                    Path.Combine(assemblyLocation, "..", "..", "..", "Data", "BadWords.en.txt")
                };

                foreach (var path in possiblePaths)
                {
                    var normalizedPath = Path.GetFullPath(path);
                    Console.WriteLine($"   🔎 Checking: {normalizedPath}");
                    
                    if (File.Exists(normalizedPath))
                    {
                        Console.WriteLine($"   ✅ Found file at: {normalizedPath}");
                        using var fileStream = File.OpenRead(normalizedPath);
                        return ReadWordsFromStream(fileStream, normalizedPath);
                    }
                }

                Console.WriteLine("❌ ERROR: BadWords.en.txt not found in embedded resources OR file system!");
                Console.WriteLine($"   Assembly location: {assemblyLocation}");
                Console.WriteLine($"   Current directory: {currentDirectory}");
                Console.WriteLine("💡 SOLUTION: Copy BadWords.en.txt to API/Data/ folder");
                
                return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ EXCEPTION: {ex.Message}");
                Console.WriteLine($"   Stack: {ex.StackTrace}");
                return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }
        }

        private static HashSet<string> ReadWordsFromStream(Stream stream, string source)
        {
            using var reader = new StreamReader(stream);
            var words = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            string? line;
            int lineCount = 0;
            while ((line = reader.ReadLine()) != null)
            {
                var word = line.Trim().ToLowerInvariant();
                if (!string.IsNullOrWhiteSpace(word))
                {
                    words.Add(word);
                    lineCount++;
                }
            }

            Console.WriteLine($"✅ Successfully loaded {words.Count} bad words from {source} ({lineCount} lines total)");
            return words;
        }
    }
}

