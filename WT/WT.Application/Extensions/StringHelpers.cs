using System.ComponentModel.DataAnnotations;
using System.Globalization;

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
                // Austria
                new CountryCode("AT", "Austria", new LatLng(48.2082, 16.3738)),
                // Canberra
                new CountryCode("AU", "Australia", new LatLng(-35.28, 149.13)),
                // Ireland
                new CountryCode("IE", "Ireland", new LatLng(53.3498, -6.2603)),
                // Belgium
                new CountryCode("BE", "Belgium", new LatLng(50.8503, 4.3517)),
                // Canberra (duplicate removed)
                // Brasilia
                new CountryCode("BR", "Brazil", new LatLng(-15.79, -47.88)),
                // Ottawa
                new CountryCode("CA", "Canada", new LatLng(45.4215, -75.6972)),
                // Berlin
                new CountryCode("DE", "Germany", new LatLng(52.5200, 13.4050)),
                // Paris
                new CountryCode("FR", "France", new LatLng(48.8566, 2.3522)),
                // Rome
                new CountryCode("IT", "Italy", new LatLng(41.9028, 12.4964)),
                // Wellington
                new CountryCode("NZ", "New Zealand", new LatLng(-40.9006, 174.8860)),
                // Warsaw
                new CountryCode("PL", "Poland", new LatLng(52.2370, 21.0173)),
                // Bucharest
                new CountryCode("RO", "Romania", new LatLng(44.4268, 26.1025)),
                // London
                new CountryCode("GB", "United Kingdom", new LatLng(55.3781, -3.4360)),
                // Washington, D.C.
                new CountryCode("US", "United States", new LatLng(37.0902, -95.7129)),
                // Spain
                new CountryCode("ES", "Spain", new LatLng(40.4637, -3.7038)),
                // Sweden
                new CountryCode("SE", "Sweden", new LatLng(60.1282, 18.6435)),
                // Norway
                new CountryCode("NO", "Norway", new LatLng(60.4720, 8.4689)),
                // Finland
                new CountryCode("FI", "Finland", new LatLng(61.9241, 25.7482)),
                // Denmark
                new CountryCode("DK", "Denmark", new LatLng(56.2639, 9.5018)),
                // Switzerland
                new CountryCode("CH", "Switzerland", new LatLng(46.8182, 8.2275)),
                // Portugal
                new CountryCode("PT", "Portugal", new LatLng(39.3999, -8.2245)),
                // Slovakia
                new CountryCode("SK", "Slovakia", new LatLng(48.6690, 19.6990)),
                // Greece
                new CountryCode("GR", "Greece", new LatLng(39.0742, 21.8243)),
                // Slovenia
                new CountryCode("SI", "Slovenia", new LatLng(46.1512, 14.9955)),
                // Peru
                new CountryCode("PE", "Peru", new LatLng(-9.1900, -75.0152)),
                // Netherlands
                new CountryCode("NL", "Netherlands", new LatLng(52.1326, 5.2913)),
                // Japan
                new CountryCode("JP", "Japan", new LatLng(36.2048, 138.2529)),
                // Uruguay
                new CountryCode("UY", "Uruguay", new LatLng(-32.5228, -55.7658)),
                // South Korea
                new CountryCode("KR", "South Korea", new LatLng(35.9078, 127.7669)),
                // Argentina
                new CountryCode("AR", "Argentina", new LatLng(-34.6037, -58.3816)),
                // Chile
                new CountryCode("CL", "Chile", new LatLng(-33.4489, -70.6693)),
                // Mexico
                new CountryCode("MX", "Mexico", new LatLng(23.6345, -102.5528)),
                // South Africa
                new CountryCode("ZA", "South Africa", new LatLng(-30.5595, 22.9375)),


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
                // food restaurant
                new PointOfInterestType("FDRT", "Restaurant"),                
                // food bar
                new PointOfInterestType("FDBR", "Bar"),
                // shop 
                new PointOfInterestType("SHOP", "Shop"),
                // Sport venue
                new PointOfInterestType("SPRT", "Sport Venue"),
                new PointOfInterestType("TOIL", "Toilet Facility"),
                new PointOfInterestType("ACCS", "Accessibility Feature"),
                new PointOfInterestType("HIST", "Historical Site"),
                //  beach
                new PointOfInterestType("BEAC", "Beach"),
                // boradwalk / dock
                new PointOfInterestType("DOCK", "Dock / Boardwalk"),
                // Lake
                new PointOfInterestType("LAKE", "Lake"),
                // River
                new PointOfInterestType("RIVR", "River"),
                // Waterfall
                new PointOfInterestType("WATR", "Waterfall"),
                // Mountain
                new PointOfInterestType("MNTN", "Mountain Peak"),

                new PointOfInterestType("NATU", "Natural Reserve"),
                new PointOfInterestType("OBST", "Obstruction"),
                new PointOfInterestType("CNST", "Construction"),
                new PointOfInterestType("OBSV", "Observation Deck"),
                // Hospital
                new PointOfInterestType("HOSP", "Hospital"),
                new PointOfInterestType("FSTN", "First Aid Station"),
                new PointOfInterestType("OTHR", "Other"),
            }.OrderBy(poi => poi.POIName).ToList();
        }


        public static List<TrailDifficulty> GetTrailDifficulties()
        {
            return new List<TrailDifficulty>
            {
                new TrailDifficulty { Code = "EASY", Title = "Easy", Description = "Smooth, flat surface suitable for all wheelchair users" },
                new TrailDifficulty { Code = "MODR", Title = "Moderate", Description = "Gentle slopes, may require some assistance" },
                new TrailDifficulty { Code = "CHAL", Title = "Challenging", Description = "Steeper grades, may require assistance or powered chair" },
                new TrailDifficulty { Code = "VERY", Title = "Very Challenging", Description = "Significant inclines, rough terrain and uneven surfaces" }
            };
        }


        public static List<TrailSurfaceType> GetTrailSurfaceType()
        {
            return new List<TrailSurfaceType>
            {
                new TrailSurfaceType { Code = "UNKW", Title = "Unknown", Description = "Surface type not specified" },
                new TrailSurfaceType { Code = "PVED", Title = "Paved", Description = "Asphalt or concrete surface" },
                new TrailSurfaceType { Code = "GRAS", Title = "Grass", Description = "Natural grass surface" },
                new TrailSurfaceType { Code = "GRVL", Title = "Gravel", Description = "Gravel or crushed stone" },
                new TrailSurfaceType { Code = "MIXD", Title = "Mixed", Description = "Mixed surface types" },
                new TrailSurfaceType { Code = "WDDK", Title = "Boardwalk /Deck", Description = "Wooden boardwalk or deck" }
            };
        }

        /// <summary>
        /// Simple serializable latitude/longitude type to avoid tuple serialization issues.
        /// </summary>
        public record LatLng(double Latitude, double Longitude);

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
            public CountryCode(string code, string name, LatLng capital)
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
            public LatLng Capital { get; set; }
        }


        public class TrailDifficulty
        {
            [Required]
            [MaxLength(4, ErrorMessage = "Code must be 4 characters long."), MinLength(4)]
            public string? Code { get; set; }
            [Required]
            [MaxLength(20, ErrorMessage = "Title has a maximum length of 20 characters.")]
            public string? Title { get; set; }
            [Required]
            [MaxLength(70, ErrorMessage = "Description has a maximum length of 70 characters.")]
            public string? Description { get; set; }
        }

        public class TrailSurfaceType
        {
            [Required]
            [MaxLength(4, ErrorMessage = "Code must be 4 characters long."), MinLength(4)]
            public string? Code { get; set; }
            [Required]
            [MaxLength(20, ErrorMessage = "Title has a maximum length of 20 characters.")]
            public string? Title { get; set; }
            [Required]
            [MaxLength(40, ErrorMessage = "Description has a maximum length of 40 characters.")]
            public string? Description { get; set; }
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
}
