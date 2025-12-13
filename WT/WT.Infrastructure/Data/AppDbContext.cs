using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WT.Domain.Entity;

namespace WT.Infrastructure.Data
{
    public class AppDbContext : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>
    {   
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // ✅ ApplicationUser → WTTrail (One-to-Many)
            builder.Entity<ApplicationUser>()
                .HasMany(u => u.Trails)
                .WithOne(t => t.User)
                .HasForeignKey(t => t.UserId)
                .OnDelete(DeleteBehavior.Cascade); // Delete trails when user is deleted

            // ✅ ApplicationUser → Comment (One-to-Many)
            builder.Entity<ApplicationUser>()
                .HasMany(u => u.Comments)
                .WithOne(c => c.User)
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Restrict); // ⚠️ Prevent cascade conflicts (see below)

            // ✅ WTTrail → WTTrailPhoto (One-to-Many)
            builder.Entity<WTTrail>()
                .HasMany(t => t.Images)
                .WithOne(p => p.Trail)
                .HasForeignKey(p => p.TrailId)
                .OnDelete(DeleteBehavior.Cascade); // Delete photos when trail is deleted

            // ✅ WTTrail → Comment (One-to-Many)
            builder.Entity<WTTrail>()
                .HasMany(t => t.Comments)
                .WithOne(c => c.Trail)
                .HasForeignKey(c => c.TrailId)
                .OnDelete(DeleteBehavior.Cascade); // Delete comments when trail is deleted

            // ✅ ApplicationUser → RefreshToken (One-to-Many)
            builder.Entity<ApplicationUser>()
                .HasMany(u => u.RefreshTokens)
                .WithOne(rt => rt.Account)
                .HasForeignKey(rt => rt.AccountId)
                .OnDelete(DeleteBehavior.Cascade);

            // ✅ ApplicationUser → TrailLike (One-to-Many)
            builder.Entity<ApplicationUser>()
                .HasMany(u => u.LikedTrails)
                .WithOne(tl => tl.User)
                .HasForeignKey(tl => tl.UserId)
                .OnDelete(DeleteBehavior.Cascade); // Delete likes when user is deleted

            // ✅ WTTrail → TrailLike (One-to-Many)
            builder.Entity<WTTrail>()
                .HasMany(t => t.Likes)
                .WithOne(tl => tl.Trail)
                .HasForeignKey(tl => tl.TrailId)
                .OnDelete(DeleteBehavior.Cascade); // Delete likes when trail is deleted

            // ✅ Create composite unique index to prevent duplicate likes
            builder.Entity<TrailLike>()
                .HasIndex(tl => new { tl.UserId, tl.TrailId })
                .IsUnique(); // A user can only like a trail once

            // ✅ Create index for performance
            builder.Entity<TrailLike>()
                .HasIndex(tl => tl.TrailId);

            builder.Entity<TrailLike>()
                .HasIndex(tl => tl.UserId);

            builder.Entity<TrailLike>()
                .HasIndex(tl => tl.LikedAt);

            // ✅ Indexes for performance
            builder.Entity<ApplicationUser>()
                .HasIndex(u => u.Username)
                .IsUnique()
                .HasFilter("[Username] IS NOT NULL");

            builder.Entity<WTTrail>()
                .HasIndex(t => t.UserId);

            builder.Entity<WTTrailPhoto>()
                .HasIndex(p => p.TrailId);

            // ✅ Comment indexes
            builder.Entity<Comment>()
                .HasIndex(c => c.TrailId);

            builder.Entity<Comment>()
                .HasIndex(c => c.UserId);

            builder.Entity<Comment>()
                .HasIndex(c => c.CreatedAt);

            // ✅ Configure enum storage as integers
            builder.Entity<WTTrail>()
                .Property(t => t.Difficulty)
                .HasConversion<int>(); // Store as int in database

            builder.Entity<WTTrail>()
                .Property(t => t.SurfaceTypes)
                .HasConversion<int>(); // Store flags enum as int

            // ✅ Add index for filtering by difficulty
            builder.Entity<WTTrail>()
                .HasIndex(t => t.Difficulty);
        }

        public DbSet<RefreshToken> RefreshTokens { get; set; } = default!;
        public DbSet<WTTrail> Trails { get; set; } = default!;
        public DbSet<WTTrailPhoto> TrailPhotos { get; set; } = default!;
        public DbSet<Comment> Comments { get; set; } = default!;
        
        // ✅ ADD: DbSet for TrailLikes
        public DbSet<TrailLike> TrailLikes { get; set; } = default!;
    }
}
