using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WT.Domain.Entity;
using WT.Domain.Geo;

namespace WT.Infrastructure.Data
{
    /// <summary>
    /// Application database context for WheelyTrails.
    /// </summary>
    public class AppDbContext : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // ApplicationUser configuration
            builder.Entity<ApplicationUser>(entity =>
            {
                entity.Property(e => e.ProfileUsername)
                    .IsRequired()
                    .HasMaxLength(20);

                entity.HasIndex(e => e.ProfileUsername)
                    .IsUnique()
                    .HasDatabaseName("IX_AspNetUsers_ProfileUsername_Unique")
                    .HasFilter("[ProfileUsername] IS NOT NULL");

                entity.HasIndex(e => e.ProfileUsernameCreatedAt)
                    .HasDatabaseName("IX_AspNetUsers_ProfileUsernameCreatedAt");
            });

            // ApplicationUser -> Trails (1 - many)
            builder.Entity<ApplicationUser>()
                .HasMany(u => u.Trails)
                .WithOne(t => t.User)
                .HasForeignKey(t => t.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // ApplicationUser -> Comments
            builder.Entity<ApplicationUser>()
                .HasMany(u => u.Comments)
                .WithOne(c => c.User)
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Restrict);

            // ApplicationUser -> TrailLike
            builder.Entity<ApplicationUser>()
                .HasMany(u => u.LikedTrails)
                .WithOne(tl => tl.User)
                .HasForeignKey(tl => tl.UserId)
                .OnDelete(DeleteBehavior.Restrict);

            // ApplicationUser -> RefreshTokens
            builder.Entity<ApplicationUser>()
                .HasMany(u => u.RefreshTokens)
                .WithOne(rt => rt.Account)
                .HasForeignKey(rt => rt.AccountId)
                .OnDelete(DeleteBehavior.Cascade);

            // WTTrail -> Photos
            builder.Entity<WTTrail>()
                .HasMany(t => t.Images)
                .WithOne(p => p.Trail)
                .HasForeignKey(p => p.TrailId)
                .OnDelete(DeleteBehavior.Cascade);

            // WTTrail -> Comments
            builder.Entity<WTTrail>()
                .HasMany(t => t.Comments)
                .WithOne(c => c.Trail)
                .HasForeignKey(c => c.TrailId)
                .OnDelete(DeleteBehavior.Cascade);

            // WTTrail -> Likes
            builder.Entity<WTTrail>()
                .HasMany(t => t.Likes)
                .WithOne(tl => tl.Trail)
                .HasForeignKey(tl => tl.TrailId)
                .OnDelete(DeleteBehavior.Cascade);

            // TrailLike indexes
            builder.Entity<TrailLike>()
                .HasIndex(tl => new { tl.UserId, tl.TrailId })
                .IsUnique();

            builder.Entity<TrailLike>().HasIndex(tl => tl.TrailId);
            builder.Entity<TrailLike>().HasIndex(tl => tl.UserId);
            builder.Entity<TrailLike>().HasIndex(tl => tl.LikedAt);

            // Indexes for users and trails
            builder.Entity<ApplicationUser>().HasIndex(u => u.UserName).IsUnique().HasFilter("[Username] IS NOT NULL");
            builder.Entity<WTTrail>().HasIndex(t => t.UserId);
            builder.Entity<WTTrail>().HasIndex(t => t.Difficulty);

            // TrailPhoto indexes
            builder.Entity<WTTrailPhoto>().HasIndex(p => p.TrailId);
            builder.Entity<WTTrailPhoto>().HasIndex(p => new { p.TrailId, p.UserId });

            // Comment indexes
            builder.Entity<Comment>().HasIndex(c => c.TrailId);
            builder.Entity<Comment>().HasIndex(c => c.UserId);
            builder.Entity<Comment>().HasIndex(c => c.CreatedAt);

            // Enum conversions
            builder.Entity<WTTrail>().Property(t => t.Difficulty).HasConversion<int>();
            builder.Entity<WTTrail>().Property(t => t.SurfaceTypes).HasConversion<int>();

            // Owned types for WTTrail
            builder.Entity<WTTrail>(b =>
            {
                b.OwnsOne(t => t.Start, sa =>
                {
                    sa.Property(p => p.Lat).HasColumnName("StartLat");
                    sa.Property(p => p.Lng).HasColumnName("StartLng");
                });

                b.OwnsOne(t => t.End, ea =>
                {
                    ea.Property(p => p.Lat).HasColumnName("EndLat");
                    ea.Property(p => p.Lng).HasColumnName("EndLng");
                });

                b.OwnsMany(t => t.Waypoints, wp =>
                {
                    wp.WithOwner().HasForeignKey("TrailId");
                    wp.Property<Guid>("Id").ValueGeneratedOnAdd();
                    wp.HasKey("Id");
                    wp.Property(p => p.Lat).HasColumnName("WaypointLat");
                    wp.Property(p => p.Lng).HasColumnName("WaypointLng");
                    wp.ToTable("TrailWaypoints");
                });

                b.OwnsMany(t => t.PointsOfInterest, poi =>
                {
                    poi.WithOwner().HasForeignKey("TrailId");
                    poi.HasKey(p => p.Id);
                    poi.Property(p => p.Type).HasMaxLength(100);
                    poi.Property(p => p.Notes).HasMaxLength(300);
                    poi.OwnsOne(p => p.Location, loc =>
                    {
                        loc.Property(l => l.Lat).HasColumnName("PoiLat");
                        loc.Property(l => l.Lng).HasColumnName("PoiLng");
                    });
                    poi.ToTable("TrailPointsOfInterest");
                });
            });

            // Index to efficiently find pending deletion items
            builder.Entity<DeletionQueueItem>().HasIndex(d => new { d.Status, d.NextAttemptAt });

            // Prevent cascade delete from TrailPhoto -> User (Identity user)
            builder.Entity<WTTrailPhoto>()
                .HasOne<ApplicationUser>() // no navigation property on photo to user
                .WithMany() // no inverse navigation on ApplicationUser
                .HasForeignKey(p => p.UserId)
                .OnDelete(DeleteBehavior.NoAction);

            // Prevent cascade delete from Trail -> User if that is also configured
            builder.Entity<WTTrail>()
                .HasOne(t => t.User)
                .WithMany(u => u.Trails)
                .HasForeignKey(t => t.UserId)
                .OnDelete(DeleteBehavior.NoAction);

            // If you have other relationships that cascade into the same target (e.g. TrailPhotos -> Trail -> User),
            // make sure at least one link in the chain is NoAction/Restrict so SQL Server has a single cascade path.
        }

        // DBSet declarations
        public DbSet<RefreshToken> RefreshTokens { get; set; } = default!;
        public DbSet<WTTrail> Trails { get; set; } = default!;
        public DbSet<WTTrailPhoto> TrailPhotos { get; set; } = default!;
        public DbSet<Comment> Comments { get; set; } = default!;
        public DbSet<TrailLike> TrailLikes { get; set; } = default!;
        public DbSet<DeletionQueueItem> DeletionQueue { get; set; } = default!;
        public DbSet<DevLogEntry> DevLogEntries { get; set; } = default!;
    }
}
