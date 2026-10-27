namespace KeyMaster.Models.API;

public sealed record LogoutRequest(
    string RefreshToken);