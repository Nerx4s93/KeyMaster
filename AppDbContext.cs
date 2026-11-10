using KeyMaster.Models;
using Microsoft.EntityFrameworkCore;

namespace KeyMaster;

public class AppDbContext : DbContext
{
    public DbSet<User> Users => Set<User>();
    public DbSet<APIKey> Keys => Set<APIKey>();
    public DbSet<VerificationCode> VerificationCodes => Set<VerificationCode>();

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>()
            .HasIndex(user => user.Login)
            .IsUnique();

        modelBuilder.Entity<User>()
            .HasMany(user => user.APIKeys)
            .WithOne(apiKey => apiKey.User)
            .HasForeignKey(apiKey => apiKey.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<VerificationCode>()
            .HasOne(x => x.User)
            .WithMany(x => x.VerificationCodes)
            .HasForeignKey(x => x.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}