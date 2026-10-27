namespace KeyMaster.Models.API;

public sealed record RegisterRequest(
    string Login,
    string Password,
    string Email);