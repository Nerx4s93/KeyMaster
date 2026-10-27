namespace KeyMaster.Models;

public sealed record CreateApiKeyRequest(
    string Name,
    string? Description,
    string Key);