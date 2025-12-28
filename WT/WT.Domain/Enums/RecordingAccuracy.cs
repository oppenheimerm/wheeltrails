
namespace WT.Domain.Enums
{
    //  Create a enuumeration for accuracy(GPS) levels when recordin a
    //  new <see cref="WT.Domain.Entity.WTTrail"/> with a default and high accuracy level
    /// <summary>
    /// Enumeration representing GPS accuracy levels.
    /// </summary>
    public enum GpsAccuracyLevel
    {
        /// <summary>
        /// Default accuracy level.  Normal accuracy for background location tracking.
        /// </summary>
        Default = 1,
        /// <summary>
        /// High accuracy level.  Uses more power for precise location tracking. Appropriate for active recording.
        /// </summary>
        High = 2
    }
}
