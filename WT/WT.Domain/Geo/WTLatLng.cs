
namespace WT.Domain.Geo
{
    /// <summary>
    /// Represents a geographical coordinate consisting of latitude and longitude. We prefix
    /// this class with "WT" to avoid conflicts with other libraries that may define similar types.
    /// </summary>
    /// <param name="Lat"></param>
    /// <param name="Lng"></param>
    public record WTLatLng(double Lat, double Lng);
}
