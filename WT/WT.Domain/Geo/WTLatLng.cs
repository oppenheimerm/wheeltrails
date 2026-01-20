
namespace WT.Domain.Geo
{
    /// <summary>
    /// Represents a geographical coordinate consisting of latitude and longitude. We prefix
    /// this class with "WT" to avoid conflicts with other libraries that may define similar types.
    /// Latitude and Longitude are for route drawing
    /// Altitude → for elevation graph
    /// Timestamp → for time-based data
    /// </summary>
    /// <param name="Lat"></param>
    /// <param name="Lng"></param>
    /// <param name="Altitude"></param>
    /// <param name="Timestamp"></param>
    public record WTLatLng(double Lat, double Lng, double? Altitude, DateTime? Timestamp);
}
