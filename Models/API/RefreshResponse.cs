namespace KeyMaster.Models.API;

public sealed record RefreshResponse(
    string AccessToken,
    DateTime ExpiresAt);