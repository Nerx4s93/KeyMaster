using KeyMaster.Models;
using KeyMaster.Models.API;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Security.Cryptography;

namespace KeyMaster.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly PasswordHasher<User> _passwordHasher = new();

    public AuthController(AppDbContext db)
    {
        _db = db;
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<ActionResult<MessageResponse>> Register(
        RegisterRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Login) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest("Логин и пароль обязательны.");
        }

        if (string.IsNullOrWhiteSpace(request.Email))
        {
            return BadRequest("Email обязателен.");
        }

        var login = request.Login.Trim();
        var email = request.Email.Trim();

        var loginExists = await _db.Users
            .AnyAsync(
                x => x.Login == login,
                cancellationToken);

        if (loginExists)
        {
            return Conflict(
                "Пользователь с таким логином уже существует.");
        }

        var user = new User
        {
            Login = login,
            Email = email,
            IsVerified = false
        };

        user.PasswordHash = _passwordHasher.HashPassword(
            user,
            request.Password);

        _db.Users.Add(user);

        await _db.SaveChangesAsync(cancellationToken);

        return Ok(new MessageResponse(
            "Пользователь зарегистрирован."));
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<ActionResult<TokenResponse>> Login(
        LoginRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Login) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest("Логин и пароль обязательны.");
        }

        var login = request.Login.Trim();

        var user = await _db.Users
            .SingleOrDefaultAsync(
                x => x.Login == login,
                cancellationToken);

        if (user is null)
        {
            return Unauthorized(
                "Неверный логин или пароль.");
        }

        var passwordResult = _passwordHasher.VerifyHashedPassword(
            user,
            user.PasswordHash,
            request.Password);

        if (passwordResult == PasswordVerificationResult.Failed)
        {
            return Unauthorized(
                "Неверный логин или пароль.");
        }

        if (passwordResult ==
            PasswordVerificationResult.SuccessRehashNeeded)
        {
            user.PasswordHash = _passwordHasher.HashPassword(
                user,
                request.Password);
        }

        var token = GenerateToken();

        var session = new UserSession
        {
            UserId = user.Id,
            Token = token,
            CreatedAt = DateTime.UtcNow
        };

        _db.UserSessions.Add(session);

        await _db.SaveChangesAsync(cancellationToken);

        return Ok(new TokenResponse(token));
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(
        CancellationToken cancellationToken)
    {
        var token = User.FindFirstValue(
            ClaimTypes.SerialNumber);

        if (string.IsNullOrWhiteSpace(token))
        {
            return Unauthorized();
        }

        var session = await _db.UserSessions
            .SingleOrDefaultAsync(
                x => x.Token == token,
                cancellationToken);

        if (session is null)
        {
            return NoContent();
        }

        _db.UserSessions.Remove(session);

        await _db.SaveChangesAsync(cancellationToken);

        return NoContent();
    }

    private static string GenerateToken()
    {
        return Convert.ToHexString(
            RandomNumberGenerator.GetBytes(32));
    }
}
