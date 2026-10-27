namespace KeyMaster.Models.API;

public sealed record RegenerateMasterKeyResponse(
    string Key,
    string Message) : MessageResponse(Message);