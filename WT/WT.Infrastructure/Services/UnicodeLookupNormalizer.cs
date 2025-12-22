using Microsoft.AspNetCore.Identity;
using System.Globalization;
using System.Text;

namespace WT.Infrastructure.Services;

/// <summary>
/// Provides Unicode-aware normalization for Identity lookups (usernames and emails).
/// </summary>
/// <remarks>
/// Identity uses normalized values (e.g. <c>NormalizedUserName</c>, <c>NormalizedEmail</c>) for lookups
/// and comparisons. The default <see cref="ILookupNormalizer"/> performs simple ASCII upper-casing
/// and can fail for internationalized input. This implementation:
/// - Applies Unicode compatibility normalization (NFKC / FormKC) to canonicalize visually-equivalent
/// Unicode sequences.
/// - Converts the resulting value to invariant upper-case for stable, case-insensitive lookups.
/// - For emails, attempts to convert the domain part to ASCII (punycode) using <see cref="IdnMapping"/>,
/// which improves matching for internationalized domain names.
///
/// Registration (recommended):
/// <code>
/// // Register before Identity is configured so Identity picks up the custom normalizer
/// services.AddSingleton<ILookupNormalizer, UnicodeLookupNormalizer>();
/// </code>
///
/// Notes:
/// - <see cref="NormalizeName(string?)"/> is intended for usernames and display-name lookups.
/// - <see cref="NormalizeEmail(string?)"/> preserves the local-part as provided but applies
/// Unicode normalization and converts the domain to punycode when possible. The combined result
/// is upper-cased to align with Identity behavior.
/// - This class does not perform validation of email syntax; it only normalizes values for lookups.
/// </remarks>
public class UnicodeLookupNormalizer : ILookupNormalizer
{
    private static string NormalizeInternal(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
            return string.Empty;

        // Canonicalize Unicode then fold to invariant upper-case for lookups
        return key.Normalize(NormalizationForm.FormKC).ToUpperInvariant();
    }

    /// <summary>
    /// Normalizes a username or name for Identity lookups.
    /// </summary>
    /// <param name="name">The input name (may be null or empty).</param>
    /// <returns>A normalized, invariant upper-case string suitable for Identity comparisons.</returns>
    public string NormalizeName(string? name) => NormalizeInternal(name);

    /// <summary>
    /// Normalizes an email address for Identity lookups.
    /// </summary>
    /// <param name="email">The email address to normalize (may be null or empty).</param>
    /// <returns>
    /// A normalized, invariant upper-case representation of the email. If the domain is internationalized,
    /// an attempt is made to convert it to ASCII/punycode for stable lookups; otherwise the domain is left
    /// unchanged.
    /// </returns>
    /// <remarks>
    /// The method splits the input on the first '@' character. Inputs that do not contain a valid
    /// local@domain structure fall back to a simple upper-cased normalization. This method intentionally
    /// does not validate email format - use dedicated validators for that purpose.
    /// </remarks>
    public string NormalizeEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return string.Empty;

        // Normalize whole string first (compat decomposition)
        var normalized = email.Normalize(NormalizationForm.FormKC);

        // Split local@domain (keep everything if no '@')
        var atIndex = normalized.IndexOf('@');
        if (atIndex <= 0 || atIndex == normalized.Length - 1)
        {
            // Not a normal email, fall back to generic normalization
            return normalized.ToUpperInvariant();
        }

        var local = normalized.Substring(0, atIndex);
        var domain = normalized.Substring(atIndex + 1);

        // Try to convert internationalized domain to ASCII (punycode). If it fails,
        // fall back to the normalized domain unchanged.
        try
        {
            var idn = new IdnMapping();
            domain = idn.GetAscii(domain);
        }
        catch
        {
            // leave domain as-is
        }

        var combined = $"{local}@{domain}";
        return combined.ToUpperInvariant();
    }
}