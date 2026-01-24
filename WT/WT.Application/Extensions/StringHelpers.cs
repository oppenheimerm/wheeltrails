using System.ComponentModel.DataAnnotations;

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
        /// Helper method to trim text to a specified maximum length, adding ellipsis if trimmed.
        /// </summary>
        /// <param name="text"></param>
        /// <param name="maxLength"></param>
        /// <returns></returns>
        public static string TrimText(string text, int maxLength)
        {
            if (string.IsNullOrEmpty(text) || maxLength <= 0)
            {
                return string.Empty;
            }
            if (text.Length <= maxLength)
            {
                return text;
            }
            return text.Substring(0, maxLength - 3) + "...";
        }

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
                // Canberra
                new CountryCode("AU", "Australia", (-35.28, 149.13)),
                // Brasilia
                new CountryCode("BZ", "Brazil", (-15.79, -47.88)),
                // Ottawa
                new CountryCode("CD", "Canada", (45.4215, -75.6972)),
                // Berlin
                new CountryCode("DE", "Germany", (52.5200, 13.4050)),
                // Paris
                new CountryCode("FR", "France", (48.8566, 2.3522)),
                // Rome
                new CountryCode("IT", "Italy", (41.9028, 12.4964)),
                // Wellington
                new CountryCode("NZ", "New Zealand", (-40.9006, 174.8860)),
                // Warsaw
                new CountryCode("PL", "Poland", (52.2370, 21.0173)),
                // Bucharest
                new CountryCode("RO", "Romania", (44.4268, 26.1025)),
                // London
                new CountryCode("UK", "United Kingdom", (55.3781, -3.4360)),
                // Washington, D.C.
                new CountryCode("US", "United States", (37.0902, -95.7129)),
                //  Spain
                new CountryCode("ES", "Spain", (40.4637, -3.7038)),
                //  Japan
                new CountryCode("JP", "Japan", (36.2048, 138.2529)),
                //  South Africa
                new CountryCode("ZA", "South Africa", (-30.5595, 22.9375)),


            }.OrderBy(code => code.Name).ToList();
        }


        public static List<PointOfInterestType> GetPointOfInterestTypes()
        {
            return new List<PointOfInterestType>
            {
                new PointOfInterestType("VIEW", "Scenic Viewpoint"),
                new PointOfInterestType("REST", "Rest Area"),
                new PointOfInterestType("INFO", "Information Center"),
                new PointOfInterestType("FOOD", "Food Stand"),
                new PointOfInterestType("TOIL", "Toilet Facility"),
                new PointOfInterestType("ACCS", "Accessibility Feature"),
                new PointOfInterestType("HIST", "Historical Site"),
                new PointOfInterestType("NATU", "Natural Reserve"),
                new PointOfInterestType("OBST", "Obstruction"),
                new PointOfInterestType("CNST", "Construction"),
                new PointOfInterestType("OBSV", "Observation Deck"),
                new PointOfInterestType("FSTN", "First Aid Station"),
            }.OrderBy(poi => poi.POIName).ToList();
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
        /// <param name="capital">Geographical coordinates of the country's capital city.</param>
        public CountryCode(string code, string name, (double latitude, double longitude) capital)
        {
            Code = code;
            Name = name;
            Capital = capital;
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

        /// <summary>
        /// This property represents the geographical coordinates of the country's capital city.
        /// It is used as fallback coordinates on the client side <see cref="WT.Domain.Entity.WTTrail"/>
        /// When you initialize the google map for a trail creation, if no start or end coordinates are provided
        /// </summary>
        public (double latitude, double longitude) Capital { get; set; }
    }


    /// <summary>
    /// Helper class representing a Point of Interest (POI) <see cref="WTPo"/>
    /// </summary>
    public class PointOfInterestType
    {
        public PointOfInterestType(string poiCode, string poiName)
        {
            {
                POICode = poiCode;
                POIName = poiName;
            }
        }

        [MaxLength(4, ErrorMessage = "POICode code must be 4 characters long and unique"), MinLength(4)]
        public string? POICode { get; set; }

        public string? POIName { get; set; }
    }

}
