namespace WT.Application.Extensions
{
    /// <summary>
    /// Provides utility methods for country code operations.
    /// </summary>
    /// <remarks>
    /// Contains helper methods for converting between country codes (ISO 3166-1 alpha-2)
    /// and country names, as well as retrieving available country options for forms.
    /// </remarks>
    public static class StringHelpers
    {
        /// <summary>
        /// Converts a country code to its full country name.
        /// </summary>
        /// <param name="countryCode">Two-letter ISO 3166-1 alpha-2 country code (e.g., "US", "GB").</param>
        /// <returns>
        /// The full country name if the code is recognized; otherwise, returns the uppercase
        /// country code or "Unknown" if the input is null or empty.
        /// </returns>
        /// <example>
        /// <code>
        /// var name = StringHelpers.GetCountryName("US"); // Returns "United States"
        /// var unknown = StringHelpers.GetCountryName("ZZ"); // Returns "ZZ"
        /// var empty = StringHelpers.GetCountryName(null); // Returns "Unknown"
        /// </code>
        /// </example>
        public static string GetCountryName(string? countryCode)
        {
            if (string.IsNullOrEmpty(countryCode)) return "Unknown";
            return countryCode.ToUpperInvariant() switch
            {
                "AU" => "Australia",
                "BZ" => "Brazil",
                "CD" => "Canada",
                "DE" => "Germany",
                "FR" => "France",
                "IT" => "Italy",
                "NZ" => "New Zealand",
                "PL" => "Poland",
                "RO" => "Romania",
                "UK" => "United Kingdom",
                "US" => "United States",
                _ => countryCode.ToUpperInvariant()
            };
        }

        /// <summary>
        /// Returns a list of available country codes with their corresponding names.
        /// </summary>
        /// <returns>
        /// A list of <see cref="CountryCode"/> objects containing two-letter ISO codes
        /// and full country names, sorted alphabetically by country name.
        /// </returns>
        /// <remarks>
        /// This method is typically used to populate dropdown lists in registration
        /// and profile forms. The list is generated on each call and contains a
        /// curated subset of countries relevant to the application.
        /// </remarks>
        /// <example>
        /// <code>
        /// var countries = StringHelpers.GetCountryCodes();
        /// foreach (var country in countries)
        /// {
        ///     Console.WriteLine($"{country.Code}: {country.Name}");
        /// }
        /// </code>
        /// </example>
        public static List<CountryCode> GetCountryCodes()
        {
            return new List<CountryCode>
            {
                new CountryCode("AU", "Australia"),
                new CountryCode("BZ", "Brazil"),
                new CountryCode("CD", "Canada"),
                new CountryCode("DE", "Germany"),
                new CountryCode("FR", "France"),
                new CountryCode("IT", "Italy"),
                new CountryCode("NZ", "New Zealand"),
                new CountryCode("PL", "Poland"),
                new CountryCode("RO", "Romania"),
                new CountryCode("UK", "United Kingdom"),
                new CountryCode("US", "United States")
            }.OrderBy(code => code.Name).ToList();
        }
    }

    /// <summary>
    /// Represents a country with its ISO 3166-1 alpha-2 code and full name.
    /// </summary>
    /// <remarks>
    /// This class is used to provide structured country data for dropdown lists
    /// and other UI elements that require country selection.
    /// </remarks>
    public class CountryCode
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CountryCode"/> class.
        /// </summary>
        /// <param name="code">Two-letter ISO 3166-1 alpha-2 country code (e.g., "US", "GB").</param>
        /// <param name="name">Full name of the country (e.g., "United States", "United Kingdom").</param>
        public CountryCode(string code, string name)
        {
            Code = code;
            Name = name;
        }

        /// <summary>
        /// Gets or sets the two-letter ISO 3166-1 alpha-2 country code.
        /// </summary>
        /// <value>A two-character uppercase country code (e.g., "US", "GB", "FR").</value>
        public string Code { get; set; }

        /// <summary>
        /// Gets or sets the full name of the country.
        /// </summary>
        /// <value>The complete country name in English (e.g., "United States", "United Kingdom").</value>
        public string Name { get; set; }
    }
}
