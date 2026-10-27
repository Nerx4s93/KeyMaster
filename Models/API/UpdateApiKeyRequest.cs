namespace KeyMaster.Models.API;

public sealed record UpdateApiKeyRequest(
    string Name,
    string? Description,
    string Key);