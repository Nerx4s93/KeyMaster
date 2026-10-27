namespace KeyMaster.Models.API;

public sealed record LoginRequest(
    string Login,
    string Password);