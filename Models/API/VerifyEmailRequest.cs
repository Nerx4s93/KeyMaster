namespace KeyMaster.Models.API;

public sealed record VerifyEmailRequest(
    string Email,
    string Code);