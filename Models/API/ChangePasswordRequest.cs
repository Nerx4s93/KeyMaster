namespace KeyMaster.Models.API;

public sealed record ChangePasswordRequest(
    string CurrentPassword,
    string NewPassword);