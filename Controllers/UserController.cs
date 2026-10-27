using KeyMaster.Models;
using KeyMaster.Models.API;
using KeyMaster.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace KeyMaster.Controllers;

[ApiController]
[Authorize]
[Route("api/user")]
public class UserController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IEmailSender _emailSender;
    private readonly PasswordHasher<User> _hasher = new();

    public UserController(
        AppDbContext db,
        IEmailSender emailSender)
    {
        _db = db;
        _emailSender = emailSender;
    }

    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        var user = await FindUser();

        if (user is null)
        {
            return Unauthorized();
        }

        return Ok(new UserResponse(
            user.Id,
            user.Login,
            user.Email,
            user.IsVerified));
    }

    [HttpPut("me/name")]
    public async Task<IActionResult> UpdateName(UpdateNameRequest request)
    {
        var user = await FindUser();

        if (user is null)
        {
            return Unauthorized();
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest("Имя обязательно.");
        }

        var name = request.Name.Trim();

        if (name == user.Login)
        {
            return BadRequest("Вы уже используете это имя.");
        }

        var nameIsTaken = await _db.Users.AnyAsync(
            x => x.Login == name && x.Id != user.Id);

        if (nameIsTaken)
        {
            return Conflict("Пользователь с таким именем уже существует.");
        }

        user.Login = name;
        await _db.SaveChangesAsync();

        return Ok(new UpdateNameResponse(
            user.Login,
            "Имя пользователя изменено."));
    }

    [HttpPut("me/password")]
    public async Task<IActionResult> UpdatePassword(ChangePasswordRequest request)
    {
        var user = await FindUser();

        if (user is null)
        {
            return Unauthorized();
        }

        if (string.IsNullOrWhiteSpace(request.CurrentPassword) ||
            string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return BadRequest("Текущий и новый пароль обязательны.");
        }

        var passwordResult = _hasher.VerifyHashedPassword(
            user,
            user.PasswordHash,
            request.CurrentPassword);

        if (passwordResult == PasswordVerificationResult.Failed)
        {
            return BadRequest("Неверный текущий пароль.");
        }

        user.PasswordHash = _hasher.HashPassword(user, request.NewPassword);
        await _db.SaveChangesAsync();

        return Ok(new MessageResponse(
            "Пароль изменен."));
    }

    [HttpPost("me/master-key/regenerate")]
    public async Task<IActionResult> RegenerateMasterKey()
    {
        var user = await FindUser();

        if (user is null)
        {
            return Unauthorized();
        }

        var key = Convert.ToBase64String(
            RandomNumberGenerator.GetBytes(32));

        user.CentralApiKeyHash = Hash(key);
        await _db.SaveChangesAsync();

        return Ok(new RegenerateMasterKeyResponse(
            key,
            "Мастер-ключ перевыпущен."));
    }

    [HttpPost("send-verification-code")]
    public async Task<IActionResult> SendVerificationCode(
        CancellationToken cancellationToken)
    {
        var user = await FindUser();

        if (user is null)
        {
            return Unauthorized();
        }

        if (user.IsVerified)
        {
            return BadRequest("Email уже подтвержден.");
        }

        var code = RandomNumberGenerator
        .GetInt32(100000, 1000000)
        .ToString();

        var verificationCode = new VerificationCode
        {
            UserId = user.Id,
            Code = code,
            ExpiresAt = DateTime.UtcNow.AddMinutes(15)
        };

        _db.VerificationCodes.Add(verificationCode);

        await _db.SaveChangesAsync();

        try
        {
            await _emailSender.SendVerificationCodeAsync(
                user.Email,
                code,
                cancellationToken);
        }
        catch
        {
            return StatusCode(
                StatusCodes.Status503ServiceUnavailable,
                "Не удалось отправить письмо.");
        }

        return Ok(new MessageResponse(
            "Код подтверждения отправлен на почту."));
    }

    [HttpPost("verify-email")]
    public async Task<IActionResult> VerifyEmail(VerifyEmailRequest request)
    {
        var user = await FindUser();

        if (user is null)
        {
            return NotFound("Пользователь не найден.");

        }

        if (user.IsVerified)
        {
            return BadRequest("Email уже подтверждён.");
        }

        if (string.IsNullOrWhiteSpace(request.Code))
        {
            return BadRequest("Код обязателен.");
        }

        var code = request.Code.Trim();

        var verificationCode = await _db.VerificationCodes
        .Where(x =>
            x.UserId == user.Id &&
            x.UsedAt == null)
        .OrderByDescending(x => x.Id)
        .FirstOrDefaultAsync();

        if (verificationCode is null)
        {
            return BadRequest("Код не найден.");
        }

        if (verificationCode.ExpiresAt <= DateTime.UtcNow)
        {
            return BadRequest("Код просрочен.");
        }

        if (verificationCode.Code != code)
        {
            return BadRequest("Неверный код.");
        }

        user.IsVerified = true;
        verificationCode.UsedAt = DateTime.UtcNow;

        await _db.SaveChangesAsync();
        return Ok(new MessageResponse(
            "Email подтвержден."));
    }

    internal static string Hash(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        return Convert.ToHexString(SHA256.HashData(bytes));
    }

    private async Task<User?> FindUser()
    {
        var userIdValue = User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (!int.TryParse(userIdValue, out var userId))
        {
            return null;
        }

        return await _db.Users.SingleOrDefaultAsync(x => x.Id == userId);
    }
}