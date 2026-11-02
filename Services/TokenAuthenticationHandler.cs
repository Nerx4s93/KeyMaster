using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace KeyMaster.Services;

public sealed class TokenAuthenticationHandler
    : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "Token";

    private readonly AppDbContext _db;

    public TokenAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        AppDbContext db)
        : base(options, logger, encoder)
    {
        _db = db;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = Request.Headers.Authorization
            .FirstOrDefault()
            ?.Trim();

        if (string.IsNullOrWhiteSpace(token))
        {
            return AuthenticateResult.NoResult();
        }

        var session = await _db.UserSessions
            .AsNoTracking()
            .Include(x => x.User)
            .SingleOrDefaultAsync(x => x.Token == token);

        if (session is null)
        {
            return AuthenticateResult.Fail("Токен недействителен.");
        }

        var claims = new[]
        {
            new Claim(
                ClaimTypes.NameIdentifier,
                session.UserId.ToString()),

            new Claim(
                ClaimTypes.Name,
                session.User.Login),

            new Claim(
                ClaimTypes.SerialNumber,
                session.Token)
        };

        var identity = new ClaimsIdentity(
            claims,
            SchemeName);

        var principal = new ClaimsPrincipal(identity);

        var ticket = new AuthenticationTicket(
            principal,
            SchemeName);

        return AuthenticateResult.Success(ticket);
    }
}
