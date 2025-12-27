using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WT.Domain.Entity;
using WT.Domain.Geo;

namespace WT.Infrastructure.Data
{
    /// <summary>
    /// Application database context for WheelyTrails.
    /// Manages entity relationships, indexes, and cascade behaviors for wheelchair-accessible trail data.
    /// </summary>
    /// <remarks>
    /// <para><strong>Database Schema Overview:</strong></para>
    /// <list type="bullet">
    /// <item><description><strong>AspNetUsers:</strong> User accounts with ASP.NET Identity integration</description></item>
    /// <item><description><strong>Trails:</strong> Wheelchair-accessible trails with location, difficulty, and surface data</description></item>
    /// <item><description><strong>TrailPhotos:</strong> Photos uploaded for trails (Firebase Storage URLs)</description></item>
    /// <item><description><strong>Comments:</strong> User comments on trails</description></item>
    /// <item><description><strong>TrailLikes:</strong> User likes and ratings on trails (junction table)</description></item>
    /// <item><description><strong>RefreshTokens:</strong> JWT refresh tokens for authentication</description></item>
    /// </list>
    /// <para><strong>Key Relationships:</strong></para>
    /// <code>
    /// ApplicationUser (1) ──→ (Many) Trails
    /// ApplicationUser (1) ──→ (Many) Comments
    /// ApplicationUser (1) ──→ (Many) TrailLikes [Restrict]
    /// WTTrail (1) ──→ (Many) TrailPhotos
    /// WTTrail (1) ──→ (Many) Comments
    /// WTTrail (1) ──→ (Many) TrailLikes [Cascade]
    /// </code>
    /// <para><strong>Cascade Delete Behaviors:</strong></para>
    /// <list type="table">
    /// <item>
    /// <term>User → Trails</term>
    /// <description>Cascade (delete trails when user is deleted)</description>
    /// </item>
    /// <item>
    /// <term>User → Comments</term>
    /// <description>Restrict (prevent deletion if user has comments)</description>
    /// </item>
    /// <item>
    /// <term>User → TrailLikes</term>
    /// <description>Restrict (prevents circular cascade path through Trails)</description>
    /// </item>
    /// <item>
    /// <term>Trail → Photos</term>
    /// <description>Cascade (delete photos when trail is deleted)</description>
    /// </item>
    /// <item>
    /// <term>Trail → Comments</term>
    /// <description>Cascade (delete comments when trail is deleted)</description>
    /// </item>
    /// <item>
    /// <term>Trail → Likes</term>
    /// <description>Cascade (delete likes when trail is deleted)</description>
    /// </item>
    /// </list>
    /// </remarks>
    public class AppDbContext : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>
    {   
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // ============================================================
            // APPLICATIONUSER CONFIGURATION
            // ============================================================
            
            // ✅ Configure ProfileUsername with unique index
            builder.Entity<ApplicationUser>(entity =>
            {
                // Make ProfileUsername required
                entity.Property(e => e.ProfileUsername)
                    .IsRequired()
                    .HasMaxLength(20);

                // ✅ Add UNIQUE index on ProfileUsername for fast lookups and URL routing
                // Used for profile URLs: /user/{profileUsername} or /@{profileUsername}
                entity.HasIndex(e => e.ProfileUsername)
                    .IsUnique()
                    .HasDatabaseName("IX_AspNetUsers_ProfileUsername_Unique")
                    .HasFilter("[ProfileUsername] IS NOT NULL");

                // ✅ Add index on ProfileUsernameCreatedAt for analytics
                entity.HasIndex(e => e.ProfileUsernameCreatedAt)
                    .HasDatabaseName("IX_AspNetUsers_ProfileUsernameCreatedAt");
            });

            // ============================================================
            // RELATIONSHIP CONFIGURATIONS
            // ============================================================

            // ✅ ApplicationUser → WTTrail (One-to-Many)
            // User creates multiple trails
            builder.Entity<ApplicationUser>()
                .HasMany(u => u.Trails)
                .WithOne(t => t.User)
                .HasForeignKey(t => t.UserId)
                .OnDelete(DeleteBehavior.Cascade); // Delete trails when user is deleted

            // ✅ ApplicationUser → Comment (One-to-Many)
            // User can write multiple comments
            // Restrict to prevent cascade conflicts (comments go through trails)
            builder.Entity<ApplicationUser>()
                .HasMany(u => u.Comments)
                .WithOne(c => c.User)
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Restrict); // Prevent cascade conflicts

            // ✅ ApplicationUser → TrailLike (One-to-Many)
            // User can like multiple trails
            // ⚠️ CRITICAL: Uses Restrict to prevent circular cascade delete path
            // Without this, deleting a user would cascade through two paths:
            //   1. User → TrailLikes (direct)
            //   2. User → Trails → TrailLikes (indirect)
            // This creates a cycle that SQL Server rejects.
            builder.Entity<ApplicationUser>()
                .HasMany(u => u.LikedTrails)
                .WithOne(tl => tl.User)
                .HasForeignKey(tl => tl.UserId)
                .OnDelete(DeleteBehavior.Restrict); // ✅ Prevent cascade delete cycle

            // ✅ ApplicationUser → RefreshToken (One-to-Many)
            // User can have multiple refresh tokens (JWT authentication)
            builder.Entity<ApplicationUser>()
                .HasMany(u => u.RefreshTokens)
                .WithOne(rt => rt.Account)
                .HasForeignKey(rt => rt.AccountId)
                .OnDelete(DeleteBehavior.Cascade);

            // ✅ WTTrail → WTTrailPhoto (One-to-Many)
            // Trail can have multiple photos
            builder.Entity<WTTrail>()
                .HasMany(t => t.Images)
                .WithOne(p => p.Trail)
                .HasForeignKey(p => p.TrailId)
                .OnDelete(DeleteBehavior.Cascade); // Delete photos when trail is deleted

            // ✅ WTTrail → Comment (One-to-Many)
            // Trail can have multiple comments
            builder.Entity<WTTrail>()
                .HasMany(t => t.Comments)
                .WithOne(c => c.Trail)
                .HasForeignKey(c => c.TrailId)
                .OnDelete(DeleteBehavior.Cascade); // Delete comments when trail is deleted

            // ✅ WTTrail → TrailLike (One-to-Many)
            // Trail can have multiple likes/ratings
            builder.Entity<WTTrail>()
                .HasMany(t => t.Likes)
                .WithOne(tl => tl.Trail)
                .HasForeignKey(tl => tl.TrailId)
                .OnDelete(DeleteBehavior.Cascade); // Keep cascade for trail deletion

            // ============================================================
            // TRAILLIKE INDEXES AND CONSTRAINTS
            // ============================================================

            // ✅ Create composite unique index to prevent duplicate likes
            // Ensures one user can only like a trail once
            builder.Entity<TrailLike>()
                .HasIndex(tl => new { tl.UserId, tl.TrailId })
                .IsUnique(); // A user can only like a trail once

            // ✅ Create indexes for performance on TrailLike queries
            builder.Entity<TrailLike>()
                .HasIndex(tl => tl.TrailId); // Fast lookup of all likes for a trail

            builder.Entity<TrailLike>()
                .HasIndex(tl => tl.UserId); // Fast lookup of all trails liked by a user

            builder.Entity<TrailLike>()
                .HasIndex(tl => tl.LikedAt); // Sort likes by timestamp

            // ============================================================
            // PERFORMANCE INDEXES
            // ============================================================

            // ✅ Indexes for ApplicationUser lookups
            builder.Entity<ApplicationUser>()
                .HasIndex(u => u.UserName)
                .IsUnique()
                .HasFilter("[Username] IS NOT NULL");

            // ✅ Indexes for Trail queries
            builder.Entity<WTTrail>()
                .HasIndex(t => t.UserId); // Find all trails by a user

            builder.Entity<WTTrail>()
                .HasIndex(t => t.Difficulty); // Filter trails by difficulty level

            // ✅ Indexes for TrailPhoto queries
            builder.Entity<WTTrailPhoto>()
                .HasIndex(p => p.TrailId); // Find all photos for a trail

            // ✅ Comment indexes for performance
            builder.Entity<Comment>()
                .HasIndex(c => c.TrailId); // Find all comments for a trail

            builder.Entity<Comment>()
                .HasIndex(c => c.UserId); // Find all comments by a user

            builder.Entity<Comment>()
                .HasIndex(c => c.CreatedAt); // Sort comments by date

            // ============================================================
            // ENUM STORAGE CONFIGURATION
            // ============================================================

            // ✅ Configure enum storage as integers (more efficient than strings)
            builder.Entity<WTTrail>()
                .Property(t => t.Difficulty)
                .HasConversion<int>(); // Store TrailDifficulty as int in database

            builder.Entity<WTTrail>()
                .Property(t => t.SurfaceTypes)
                .HasConversion<int>(); // Store SurfaceType flags enum as int

            // ============================================================
            // VALUE OBJECT / OWNED TYPE MAPPINGS
            // ============================================================
            // Explanation:
            // - EF Core will attempt to map any non-primitive CLR type referenced by an entity
            // as an entity type unless configured otherwise. Because `WTLatLng` is a simple
            // value object (latitude/longitude) we must tell EF to treat it as an *owned* type
            // (value object) so it is stored as columns on the owner (WTTrail) or in an owned
            // collection table. This avoids the "requires a primary key" migration error.
            // - `Start` and `End` are single owned instances -> use `OwnsOne` and map to columns
            // on the `Trails` table.
            // - `Waypoints` is a collection of value objects -> use `OwnsMany` and store in
            // separate table `TrailWaypoints` with a shadow `Id` key so EF can track items.
            // - `PointsOfInterest` is modelled as an owned collection here. Each POI has its own
            // `Id` (domain entity-like) so we use that as the key and own its `Location` too.

            builder.Entity<WTTrail>(b =>
            {
                // Start coordinates stored as columns on Trails: StartLat, StartLng
                b.OwnsOne(t => t.Start, sa =>
                {
                    sa.Property(p => p.Lat).HasColumnName("StartLat");
                    sa.Property(p => p.Lng).HasColumnName("StartLng");
                });

                // End coordinates stored as columns on Trails: EndLat, EndLng
                b.OwnsOne(t => t.End, ea =>
                {
                    ea.Property(p => p.Lat).HasColumnName("EndLat");
                    ea.Property(p => p.Lng).HasColumnName("EndLng");
                });

                // Waypoints: owned collection stored in separate table `TrailWaypoints`.
                // Use a shadow `Id` so EF can track collection elements.
                b.OwnsMany(t => t.Waypoints, wp =>
                {
                    wp.WithOwner().HasForeignKey("TrailId");
                    wp.Property<Guid>("Id").ValueGeneratedOnAdd();
                    wp.HasKey("Id");
                    wp.Property(p => p.Lat).HasColumnName("WaypointLat");
                    wp.Property(p => p.Lng).HasColumnName("WaypointLng");
                    wp.ToTable("TrailWaypoints");
                });

                // PointsOfInterest: owned collection. WTPointOfInterest has an Id in the domain
                // so we use it as the primary key for the owned items. We also own the POI's
                // Location (WTLatLng) as a nested owned object.
                b.OwnsMany(t => t.PointsOfInterest, poi =>
                {
                    poi.WithOwner().HasForeignKey("TrailId");
                    poi.HasKey(p => p.Id);

                    // Limit lengths at the DB level for POI strings
                    poi.Property(p => p.Type).HasMaxLength(100);
                    poi.Property(p => p.Notes).HasMaxLength(300);

                    // POI.Location is also a WTLatLng value object -> own it here
                    poi.OwnsOne(p => p.Location, loc =>
                    {
                        loc.Property(l => l.Lat).HasColumnName("PoiLat");
                        loc.Property(l => l.Lng).HasColumnName("PoiLng");
                    });

                    poi.ToTable("TrailPointsOfInterest");
                });
            });

        }

        // ============================================================
        // DBSET DECLARATIONS
        // ============================================================

        /// <summary>
        /// JWT refresh tokens for user authentication sessions.
        /// Supports token rotation and revocation for enhanced security.
        /// </summary>
        public DbSet<RefreshToken> RefreshTokens { get; set; } = default!;

        /// <summary>
        /// Wheelchair-accessible trails with location, difficulty, and surface data.
        /// Core entity of the application.
        /// </summary>
        public DbSet<WTTrail> Trails { get; set; } = default!;

        /// <summary>
        /// Photos uploaded for trails, stored in Firebase Cloud Storage.
        /// Contains Firebase Storage URLs and optional descriptions.
        /// </summary>
        public DbSet<WTTrailPhoto> TrailPhotos { get; set; } = default!;

        /// <summary>
        /// User comments on trails (max 300 characters).
        /// Cascade deleted when trail is deleted, restricted when user is deleted.
        /// </summary>
        public DbSet<Comment> Comments { get; set; } = default!;
        
        /// <summary>
        /// Junction table for Many-to-Many relationship between Users and Trails.
        /// Represents user "likes" on trails with optional 1-5 star ratings.
        /// </summary>
        /// <remarks>
        /// <para><strong>Purpose:</strong></para>
        /// <list type="bullet">
        /// <item><description>Track which users liked which trails</description></item>
        /// <item><description>Store optional 1-5 star ratings</description></item>
        /// <item><description>Record timestamp of when trail was liked</description></item>
        /// <item><description>Prevent duplicate likes (composite unique index on UserId + TrailId)</description></item>
        /// </list>
        /// <para><strong>Key Features:</strong></para>
        /// <list type="bullet">
        /// <item><description><strong>Unique Constraint:</strong> One like per user per trail</description></item>
        /// <item><description><strong>Optional Rating:</strong> Users can like without rating (Rating = null)</description></item>
        /// <item><description><strong>Timestamp Tracking:</strong> LikedAt field for analytics</description></item>
        /// <item><description><strong>Performance Indexes:</strong> Indexed on UserId, TrailId, and LikedAt</description></item>
        /// </list>
        /// <para><strong>Cascade Delete Behavior:</strong></para>
        /// <list type="table">
        /// <item>
        /// <term>When User is Deleted:</term>
        /// <description>Restrict (manual cleanup required to prevent cascade cycle)</description>
        /// </item>
        /// <item>
        /// <term>When Trail is Deleted:</term>
        /// <description>Cascade (all likes for that trail are automatically deleted)</description>
        /// </item>
        /// </list>
        /// <para><strong>Usage Example:</strong></para>
        /// <code>
        /// // Like a trail
        /// var like = new TrailLike
        /// {
        ///     UserId = currentUserId,
        ///     TrailId = trailId,
        ///     LikedAt = DateTime.UtcNow,
        ///     Rating = 5  // Optional
        /// };
        /// _context.TrailLikes.Add(like);
        /// await _context.SaveChangesAsync();
        /// 
        /// // Get all likes for a trail
        /// var likes = await _context.TrailLikes
        ///     .Where(tl => tl.TrailId == trailId)
        ///     .Include(tl => tl.User)
        ///     .ToListAsync();
        /// 
        /// // Check if user already liked this trail
        /// var alreadyLiked = await _context.TrailLikes
        ///     .AnyAsync(tl => tl.UserId == userId && tl.TrailId == trailId);
        /// </code>
        /// <para><strong>Database Schema:</strong></para>
        /// <code>
        /// CREATE TABLE [TrailLikes] (
        ///     [Id] INT IDENTITY(1,1) PRIMARY KEY,
        ///     [UserId] UNIQUEIDENTIFIER NOT NULL,
        ///     [TrailId] UNIQUEIDENTIFIER NOT NULL,
        ///     [LikedAt] DATETIME2 NOT NULL,
        ///     [Rating] INT NULL CHECK ([Rating] BETWEEN 1 AND 5),
        ///     CONSTRAINT [FK_TrailLikes_Users] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers]([Id]) ON DELETE NO ACTION,
        ///     CONSTRAINT [FK_TrailLikes_Trails] FOREIGN KEY ([TrailId]) REFERENCES [Trails]([Id]) ON DELETE CASCADE,
        ///     CONSTRAINT [UQ_TrailLikes_UserId_TrailId] UNIQUE ([UserId], [TrailId])
        /// );
        /// CREATE INDEX [IX_TrailLikes_TrailId] ON [TrailLikes]([TrailId]);
        /// CREATE INDEX [IX_TrailLikes_UserId] ON [TrailLikes]([UserId]);
        /// CREATE INDEX [IX_TrailLikes_LikedAt] ON [TrailLikes]([LikedAt]);
        /// </code>
        /// </remarks>
        public DbSet<TrailLike> TrailLikes { get; set; } = default!;
    }
}
