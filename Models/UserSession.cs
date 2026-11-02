namespace KeyMaster.Models;

public sealed class UserSession
{
    public int Id { get; set; }

    public int UserId { get; set; }
    public User User { get; set; } = null!;

    public string Token { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }
}
