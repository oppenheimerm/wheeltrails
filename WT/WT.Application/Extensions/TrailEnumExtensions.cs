using System.ComponentModel.DataAnnotations;
using System.Reflection;
using WT.Domain.Enums;

namespace WT.Application.Extensions
{
    /// <summary>
    /// Extension methods for Trail-related enumerations.
    /// </summary>
    public static class TrailEnumExtensions
    {
        /// <summary>
        /// Gets the display name from the Display attribute.
        /// </summary>
        public static string GetDisplayName(this TrailDifficulty difficulty)
        {
            var field = difficulty.GetType().GetField(difficulty.ToString());
            var attribute = field?.GetCustomAttribute<DisplayAttribute>();
            return attribute?.Name ?? difficulty.ToString();
        }

        /// <summary>
        /// Gets the description from the Display attribute.
        /// </summary>
        public static string GetDescription(this TrailDifficulty difficulty)
        {
            var field = difficulty.GetType().GetField(difficulty.ToString());
            var attribute = field?.GetCustomAttribute<DisplayAttribute>();
            return attribute?.Description ?? string.Empty;
        }

        /// <summary>
        /// Gets the display name for a surface type.
        /// </summary>
        public static string GetDisplayName(this SurfaceType surfaceType)
        {
            var field = surfaceType.GetType().GetField(surfaceType.ToString());
            var attribute = field?.GetCustomAttribute<DisplayAttribute>();
            return attribute?.Name ?? surfaceType.ToString();
        }

        /// <summary>
        /// Gets all selected surface types from a flags enum.
        /// </summary>
        /// <example>
        /// var surfaces = (SurfaceType.Paved | SurfaceType.Gravel).GetSelectedSurfaces();
        /// // Returns: ["Paved", "Gravel"]
        /// </example>
        public static List<string> GetSelectedSurfaces(this SurfaceType surfaceType)
        {
            var selectedSurfaces = new List<string>();

            foreach (SurfaceType value in Enum.GetValues(typeof(SurfaceType)))
            {
                if (value != SurfaceType.None && surfaceType.HasFlag(value))
                {
                    selectedSurfaces.Add(value.GetDisplayName());
                }
            }

            return selectedSurfaces;
        }

        /// <summary>
        /// Gets all available trail difficulty options for dropdowns.
        /// </summary>
        public static List<TrailDifficultyOption> GetDifficultyOptions()
        {
            return Enum.GetValues<TrailDifficulty>()
                .Select(d => new TrailDifficultyOption
                {
                    Value = (int)d,
                    Name = d.GetDisplayName(),
                    Description = d.GetDescription()
                })
                .ToList();
        }

        /// <summary>
        /// Gets all available surface type options for checkboxes.
        /// </summary>
        public static List<SurfaceTypeOption> GetSurfaceTypeOptions()
        {
            return Enum.GetValues<SurfaceType>()
                .Where(s => s != SurfaceType.None)
                .Select(s => new SurfaceTypeOption
                {
                    Value = (int)s,
                    Name = s.GetDisplayName(),
                    Description = s.GetType()
                        .GetField(s.ToString())?
                        .GetCustomAttribute<DisplayAttribute>()?
                        .Description ?? string.Empty
                })
                .ToList();
        }
    }

    /// <summary>
    /// DTO for trail difficulty dropdown options.
    /// </summary>
    public class TrailDifficultyOption
    {
        public int Value { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }

    /// <summary>
    /// DTO for surface type checkbox options.
    /// </summary>
    public class SurfaceTypeOption
    {
        public int Value { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }
}
