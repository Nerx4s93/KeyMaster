namespace KeyMaster.Models;

public sealed class User
{
    public int Id { get; set; }
    public string Login { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public bool IsVerified { get; set; }

    public string? CentralApiKeyHash { get; set; }

    public ICollection<RefreshToken> RefreshTokens { get; set; } = [];
    public ICollection<APIKey> APIKeys { get; set; } = [];
    public ICollection<VerificationCode> VerificationCodes { get; set; } = [];
}