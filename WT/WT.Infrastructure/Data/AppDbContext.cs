using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WT.Domain.Entity;

namespace WT.Infrastructure.Data
{
    public class AppDbContext : IdentityDbContext<ApplicationUser, WTRole, Guid>
    {   
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            

            // Configure WTRole entity
            builder.Entity<WTRole>(entity =>
            {
                entity.Property(e => e.RoleCode).IsRequired(true);
                entity.Property(e => e.Description).IsRequired(false);
            });

            // Additional model configurations can be added here
            
        }

        public DbSet<WTUserRole> WTUserRoles { get; set; } = default!;

    }
}
