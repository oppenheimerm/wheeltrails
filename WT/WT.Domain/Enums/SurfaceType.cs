using System.ComponentModel.DataAnnotations;

namespace WT.Domain.Enums
{
    /// <summary>
    /// Represents surface types that can be found on wheelchair-accessible trails.
    /// Can be combined using flags for trails with multiple surface types.
    /// </summary>
    [Flags]
    public enum SurfaceType
    {
        /// <summary>
        /// No surface type specified
        /// </summary>
        [Display(Name = "Unknown", Description = "Surface type not specified")]
        None = 0,

        /// <summary>
        /// Paved surface (asphalt, concrete)
        /// </summary>
        [Display(Name = "Paved", Description = "Asphalt or concrete surface")]
        Paved = 1 << 0, // 1

        /// <summary>
        /// Grass surface
        /// </summary>
        [Display(Name = "Grass", Description = "Natural grass surface")]
        Grass = 1 << 1, // 2

        /// <summary>
        /// Gravel or crushed stone surface
        /// </summary>
        [Display(Name = "Gravel", Description = "Gravel or crushed stone")]
        Gravel = 1 << 2, // 4

        /// <summary>
        /// Wooden boardwalk
        /// </summary>
        [Display(Name = "Boardwalk", Description = "Wooden boardwalk or deck")]
        Boardwalk = 1 << 3, // 8

        /// <summary>
        /// Paved road
        /// </summary>
        [Display(Name = "Road", Description = "Paved road or street")]
        Road = 1 << 4, // 16

        /// <summary>
        /// Dirt or natural earth surface
        /// </summary>
        [Display(Name = "Dirt", Description = "Natural dirt or earth surface")]
        Dirt = 1 << 5, // 32

        /// <summary>
        /// Rubber or synthetic surface
        /// </summary>
        [Display(Name = "Rubber", Description = "Rubber or synthetic surface")]
        Rubber = 1 << 6 // 64
    }
}
