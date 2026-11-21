using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

namespace KeyMaster.Services;

public sealed class TokenAuthenticationHandler
    : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "Token";
    public const string UserIdHeaderName = "X-User-Id";

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
        var signature = Request.Headers.Authorization
            .FirstOrDefault()?.Trim();

        if (string.IsNullOrWhiteSpace(signature))
        {
            return AuthenticateResult.NoResult();
        }

        var userIdValue = Request.Headers[UserIdHeaderName]
            .FirstOrDefault()?.Trim();

        if (!int.TryParse(userIdValue, out var userId))
        {
            return AuthenticateResult.Fail("Не указан идентификатор пользователя.");
        }

        var user = await _db.Users
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.Id == userId);

        if (user is null || user.SessionToken is null)
        {
            return AuthenticateResult.Fail("Токен недействителен.");
        }

        byte[] providedSignature;

        try
        {
            providedSignature = Convert.FromHexString(signature);
        }
        catch (FormatException)
        {
            return AuthenticateResult.Fail("Некорректная подпись.");
        }

        var body = await ReadBodyAsync();

        var path = Request.PathBase.Add(Request.Path).Value
            ?? string.Empty;

        var query = Request.QueryString.Value
            ?.TrimStart('?')
            ?? string.Empty;

        var expectedSignature = RequestSignature.Compute(
            Request.Method,
            path,
            query,
            body,
            user.SessionToken);

        if (!CryptographicOperations.FixedTimeEquals(
                providedSignature,
                expectedSignature))
        {
            return AuthenticateResult.Fail("Неверная подпись.");
        }

        var claims = new[]
        {
            new Claim(
                ClaimTypes.NameIdentifier,
                user.Id.ToString()),

            new Claim(
                ClaimTypes.Name,
                user.Login)
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

    private async Task<string> ReadBodyAsync()
    {
        if (!HttpMethods.IsPost(Request.Method) &&
            !HttpMethods.IsPut(Request.Method) &&
            !HttpMethods.IsPatch(Request.Method) &&
            !HttpMethods.IsDelete(Request.Method))
        {
            return string.Empty;
        }

        Request.EnableBuffering();

        using var reader = new StreamReader(
            Request.Body,
            Encoding.UTF8,
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 1024,
            leaveOpen: true);

        var body = await reader.ReadToEndAsync(
            Context.RequestAborted);

        Request.Body.Position = 0;

        return body;
    }
}
