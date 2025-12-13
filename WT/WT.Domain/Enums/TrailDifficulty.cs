using System.ComponentModel.DataAnnotations;

namespace WT.Domain.Enums
{
    /// <summary>
    /// Represents the difficulty level of a wheelchair-accessible trail.
    /// </summary>
    public enum TrailDifficulty
    {
        /// <summary>
        /// Easy - Suitable for all wheelchair users. Smooth, flat surface with minimal obstacles.
        /// </summary>
        [Display(Name = "Easy", Description = "Smooth, flat surface suitable for all wheelchair users")]
        Easy = 0,

        /// <summary>
        /// Moderate - Some gradual inclines, generally accessible surface.
        /// </summary>
        [Display(Name = "Moderate", Description = "Gentle slopes, may require some assistance")]
        Moderate = 1,

        /// <summary>
        /// Challenging - Steeper grades, uneven surfaces, may require assistance.
        /// </summary>
        [Display(Name = "Challenging", Description = "Steeper grades, may require assistance or powered chair")]
        Challenging = 2,

        /// <summary>
        /// Very Challenging - Significant inclines, rough terrain, specialized equipment recommended.
        /// </summary>
        [Display(Name = "Very Challenging", Description = "Significant inclines, specialized wheelchair recommended")]
        VeryDifficult = 3
    }
}
