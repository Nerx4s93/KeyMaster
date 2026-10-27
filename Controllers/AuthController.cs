using KeyMaster.Models;
using KeyMaster.Models.API;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace KeyMaster.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private const int RefreshTokenLifetimeDays = 30;

    private readonly AppDbContext _db;
    private readonly IConfiguration _configuration;
    private readonly PasswordHasher<User> _passwordHasher = new();

    public AuthController(
        AppDbContext db,
        IConfiguration configuration)
    {
        _db = db;
        _configuration = configuration;
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

        var accessToken = CreateAccessToken(user);
        var refreshTokenValue = GenerateRefreshToken();

        var refreshToken = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = HashToken(refreshTokenValue),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(
                RefreshTokenLifetimeDays),
            AccessTokenJti = accessToken.Jti,
            AccessTokenExpiresAt = accessToken.ExpiresAt
        };

        _db.RefreshTokens.Add(refreshToken);

        await _db.SaveChangesAsync(cancellationToken);

        return Ok(new TokenResponse(
            AccessToken: accessToken.Token,
            RefreshToken: refreshTokenValue,
            ExpiresAt: accessToken.ExpiresAt));
    }

    [AllowAnonymous]
    [HttpPost("refresh")]
    public async Task<ActionResult<TokenResponse>> Refresh(
        RefreshRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return Unauthorized("Refresh token отсутствует.");
        }

        var refreshTokenValue = request.RefreshToken.Trim();
        var tokenHash = HashToken(refreshTokenValue);

        var refreshToken = await _db.RefreshTokens
            .SingleOrDefaultAsync(
                x => x.TokenHash == tokenHash,
                cancellationToken);

        if (refreshToken is null ||
            refreshToken.RevokedAt is not null ||
            refreshToken.ExpiresAt <= DateTime.UtcNow)
        {
            return Unauthorized(
                "Refresh token недействителен или просрочен.");
        }

        var user = await _db.Users
            .SingleOrDefaultAsync(
                x => x.Id == refreshToken.UserId,
                cancellationToken);

        if (user is null)
        {
            return Unauthorized("Пользователь не найден.");
        }

        refreshToken.RevokedAt = DateTime.UtcNow;

        await RevokeAccessTokenAsync(
            refreshToken.AccessTokenJti,
            refreshToken.AccessTokenExpiresAt,
            cancellationToken);

        var newRefreshTokenValue = GenerateRefreshToken();
        var accessToken = CreateAccessToken(user);

        var newRefreshToken = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = HashToken(newRefreshTokenValue),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(
                RefreshTokenLifetimeDays),
            AccessTokenJti = accessToken.Jti,
            AccessTokenExpiresAt = accessToken.ExpiresAt
        };

        _db.RefreshTokens.Add(newRefreshToken);

        await CleanupRevokedTokensAsync(cancellationToken);

        await _db.SaveChangesAsync(cancellationToken);

        return Ok(new TokenResponse(
            AccessToken: accessToken.Token,
            RefreshToken: newRefreshTokenValue,
            ExpiresAt: accessToken.ExpiresAt));
    }

    [AllowAnonymous]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(
        LogoutRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return NoContent();
        }

        var tokenHash = HashToken(
            request.RefreshToken.Trim());

        var refreshToken = await _db.RefreshTokens
            .SingleOrDefaultAsync(
                x => x.TokenHash == tokenHash,
                cancellationToken);

        if (refreshToken is not null)
        {
            if (refreshToken.RevokedAt is null)
            {
                refreshToken.RevokedAt = DateTime.UtcNow;
            }

            await RevokeAccessTokenAsync(
                refreshToken.AccessTokenJti,
                refreshToken.AccessTokenExpiresAt,
                cancellationToken);

            await CleanupRevokedTokensAsync(cancellationToken);

            await _db.SaveChangesAsync(cancellationToken);
        }

        return NoContent();
    }

    private TokenResult CreateAccessToken(User user)
    {
        var jwtSettings = _configuration
            .GetSection("Jwt");

        var secretKey = jwtSettings["SecretKey"]
            ?? throw new InvalidOperationException(
                "Jwt:SecretKey is not configured.");

        var issuer = jwtSettings["Issuer"]
            ?? throw new InvalidOperationException(
                "Jwt:Issuer is not configured.");

        var audience = jwtSettings["Audience"]
            ?? throw new InvalidOperationException(
                "Jwt:Audience is not configured.");

        var expiresMinutes = int.TryParse(
            jwtSettings["ExpiresMinutes"],
            out var minutes)
            ? minutes
            : 15;

        if (expiresMinutes <= 0)
        {
            throw new InvalidOperationException(
                "Jwt:ExpiresMinutes must be greater than zero.");
        }

        var expiresAt = DateTime.UtcNow.AddMinutes(
            expiresMinutes);

        var jti = Guid.NewGuid().ToString("N");

        var claims = new[]
        {
            new Claim(
                ClaimTypes.NameIdentifier,
                user.Id.ToString()),

            new Claim(
                ClaimTypes.Name,
                user.Login),

            new Claim(
                JwtRegisteredClaimNames.Jti,
                jti)
        };

        var securityKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(secretKey));

        var credentials = new SigningCredentials(
            securityKey,
            SecurityAlgorithms.HmacSha256);

        var jwt = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: expiresAt,
            signingCredentials: credentials);

        var token = new JwtSecurityTokenHandler()
            .WriteToken(jwt);

        return new TokenResult(
            Token: token,
            ExpiresAt: expiresAt,
            Jti: jti);
    }

    private async Task RevokeAccessTokenAsync(
        string? jti,
        DateTime? expiresAt,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(jti))
        {
            return;
        }

        var isAlreadyRevoked = await _db.RevokedAccessTokens
            .AnyAsync(x => x.Jti == jti, cancellationToken);

        if (isAlreadyRevoked)
        {
            return;
        }

        _db.RevokedAccessTokens.Add(new RevokedAccessToken
        {
            Jti = jti,
            ExpiresAt = expiresAt ?? DateTime.UtcNow.AddHours(1),
            RevokedAt = DateTime.UtcNow
        });
    }

    private async Task CleanupRevokedTokensAsync(
        CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;

        var expiredTokens = await _db.RevokedAccessTokens
            .Where(x => x.ExpiresAt <= now)
            .ToListAsync(cancellationToken);

        if (expiredTokens.Count > 0)
        {
            _db.RevokedAccessTokens.RemoveRange(expiredTokens);
        }
    }

    private static string GenerateRefreshToken()
    {
        return Convert.ToBase64String(
            RandomNumberGenerator.GetBytes(64));
    }

    private static string HashToken(string token)
    {
        var bytes = Encoding.UTF8.GetBytes(token);

        return Convert.ToHexString(
            SHA256.HashData(bytes));
    }

    private sealed record TokenResult(
        string Token,
        DateTime ExpiresAt,
        string Jti);
}