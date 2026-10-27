namespace KeyMaster.Models;

public sealed class APIKey
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    // Base64: nonce (12) + ciphertext + tag (16), AES-256-GCM.
    public string Key { get; set; } = string.Empty;

    public int UserId { get; set; }
    public User User { get; set; } = null!;
}