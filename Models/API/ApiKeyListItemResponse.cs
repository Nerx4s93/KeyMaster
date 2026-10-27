namespace KeyMaster.Models.API;

public sealed record ApiKeyListItemResponse(
    int Id,
    string Name,
    string Description);
