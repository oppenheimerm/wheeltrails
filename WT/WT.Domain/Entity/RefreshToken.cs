
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Security.Principal;

namespace WT.Domain.Entity
{
    /// <summary>
    /// Represents a refresh token used for authentication and session management.
    /// </summary>
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [ForeignKey(nameof(Account))]
        public Guid? AccountId { get; set; }
        public ApplicationUser? Account { get; set; }
        public string? Token { get; set; }
        public DateTime? Expires { get; set; }
        public DateTime? Created { get; set; }
        public string? CreatedByIp { get; set; }
        public DateTime? Revoked { get; set; }
        public string? RevokedByIp { get; set; }
        public string? ReplacedByToken { get; set; }
        public string? ReasonRevoked { get; set; }
        public bool IsExpired => DateTime.UtcNow >= Expires;
        public bool IsRevoked => Revoked != null;
        public bool IsActive => Revoked == null && !IsExpired;
    }
}
