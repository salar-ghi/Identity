using IdentityServerWebApi.Domain;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityServerWebApi.Infrastructure;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }
    public DbSet<Role> Roles { get; set; }
    public DbSet<RoleClaim> RoleClaims { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ApplicationUser>(b =>
        {
            b.Property(e => e.FirstName).HasMaxLength(50);
            b.Property(e => e.LastName).HasMaxLength(50);
        });
        base.OnModelCreating(modelBuilder);
    }
}
