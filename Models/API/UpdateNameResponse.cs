namespace KeyMaster.Models.API;

public sealed record UpdateNameResponse(
    string Login,
    string Message)
    : MessageResponse(Message);