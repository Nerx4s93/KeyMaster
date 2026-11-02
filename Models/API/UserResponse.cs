namespace KeyMaster.Models.API;

public sealed record UserResponse(
    int Id,
    string Login,
    string Email,
    bool isVerified);