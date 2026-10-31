using Auth.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.Infrastructure.Configurations;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("RefreshTokens", "auth");
        builder.HasKey(t => t.Id);
        builder.Property(t => t.UserId).HasMaxLength(128).IsRequired();
        builder.Property(t => t.TokenHash).HasMaxLength(64).IsRequired();
        builder.Property(t => t.CreatedByIp).HasMaxLength(45);
        builder.Property(t => t.RevokedReason).HasMaxLength(50);
        builder.HasIndex(t => t.TokenHash).IsUnique();
        builder.HasIndex(t => t.TokenFamily);
        builder.HasIndex(t => t.UserId);
    }
}
