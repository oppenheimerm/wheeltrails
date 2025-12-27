using System;

namespace WT.Domain.Geo
{
    /// <summary>
    /// Domain entity representing a Point of Interest (POI) for an instance of a
    /// <see cref="WT.Domain.Entity.WTTrail"/> with location, type, and notes.
    /// Domain enforces validation in constructors / methods rather than using data annotations.
    /// </summary>
    public class WTPointOfInterest
    {
        /// <summary>
        /// Primary identifier for the POI.
        /// </summary>
        public Guid Id { get; private set; }

        /// <summary>
        /// Geographical location of the POI.
        /// </summary>
        public WTLatLng Location { get; private set; } = default!;

        /// <summary>
        /// Type of POI (e.g. "View", "Accessibility").
        /// </summary>
        public string Type { get; private set; } = string.Empty;

        /// <summary>
        /// Optional notes about the POI. Max length enforced by domain logic.
        /// </summary>
        public string Notes { get; private set; } = string.Empty;

        /// <summary>
        /// Creation timestamp (UTC).
        /// </summary>
        public DateTime CreatedAt { get; private set; }

        // Parameterless ctor for EF Core
        protected WTPointOfInterest() { }

        /// <summary>
        /// Create a new POI with validation applied.
        /// </summary>
        /// <param name="location">Non-null geographical location.</param>
        /// <param name="type">Non-empty type string.</param>
        /// <param name="notes">Optional notes (max300 chars).</param>
        public WTPointOfInterest(WTLatLng location, string type, string? notes = null)
        {
            Location = location ?? throw new ArgumentNullException(nameof(location));

            if (string.IsNullOrWhiteSpace(type))
                throw new ArgumentException("Type is required.", nameof(type));

            Type = type.Trim();

            Notes = (notes ?? string.Empty).Trim();
            if (Notes.Length > 300)
                throw new ArgumentException("Notes have a maximum length of300 characters.", nameof(notes));

            Id = Guid.NewGuid();
            CreatedAt = DateTime.UtcNow;
        }

        /// <summary>
        /// Update notes with domain validation.
        /// </summary>
        public void UpdateNotes(string? notes)
        {
            var n = (notes ?? string.Empty).Trim();
            if (n.Length > 300)
                throw new ArgumentException("Notes have a maximum length of300 characters.", nameof(notes));

            Notes = n;
        }

        /// <summary>
        /// Update the POI type with validation.
        /// </summary>
        public void UpdateType(string type)
        {
            if (string.IsNullOrWhiteSpace(type))
                throw new ArgumentException("Type is required.", nameof(type));

            Type = type.Trim();
        }
    }
}
