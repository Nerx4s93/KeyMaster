namespace KeyMaster.Models.API;

public sealed record ApiKeyResponse(
    int Id,
    string Name,
    string Description,
    string Key);