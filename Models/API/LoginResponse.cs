namespace KeyMaster.Models.API;

public sealed record LoginResponse(
    string AccessToken,
    DateTime ExpiresAt);