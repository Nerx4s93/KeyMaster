using DotNetEnv;
using KeyMaster.Options;
using KeyMaster.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace KeyMaster;

public class Program
{
    public static void Main(string[] args)
    {
        Env.Load();

        var builder = WebApplication.CreateBuilder(args);

        #region database

        var connectionString =
            builder.Configuration.GetConnectionString("Default")
            ?? throw new InvalidOperationException("ConnectionStrings:Default is not configured.");

        builder.Services.AddDbContext<AppDbContext>(options =>
            options.UseSqlite(connectionString));

        #endregion

        #region email

        builder.Services
            .AddOptions<EmailOptions>()
            .Bind(builder.Configuration.GetSection("Email"))
            .Validate(options => !string.IsNullOrWhiteSpace(options.Host), "Email:Host is required.")
            .Validate(options => options.Port > 0, "Email:Port must be greater than zero.")
            .Validate(options => !string.IsNullOrWhiteSpace(options.UserName), "Email:UserName is required.")
            .Validate(options => !string.IsNullOrWhiteSpace(options.Password), "Email:Password is required.")
            .Validate(options => !string.IsNullOrWhiteSpace(options.From), "Email:From is required.")
            .ValidateOnStart();

        builder.Services
            .AddOptions<EmailOptions>()
            .Bind(builder.Configuration.GetSection("Email"))
            .ValidateOnStart();

        builder.Services.AddScoped<IEmailSender, MailKitEmailSender>();

        #endregion

        #region JWT

        var jwtSettings = builder.Configuration.GetSection("Jwt");

        var secretKeyValue = jwtSettings["SecretKey"]
            ?? throw new InvalidOperationException("Jwt:SecretKey is not configured.");

        var issuer = jwtSettings["Issuer"]
            ?? throw new InvalidOperationException("Jwt:Issuer is not configured.");

        var audience = jwtSettings["Audience"]
            ?? throw new InvalidOperationException("Jwt:Audience is not configured.");

        var secretKey = Encoding.UTF8.GetBytes(secretKeyValue);

        builder.Services
            .AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme =
                    JwtBearerDefaults.AuthenticationScheme;

                options.DefaultChallengeScheme =
                    JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters =
                    new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,

                        ValidIssuer = issuer,
                        ValidAudience = audience,
                        IssuerSigningKey =
                            new SymmetricSecurityKey(secretKey)
                    };

                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        var jti = context.Principal?
                            .FindFirst(JwtRegisteredClaimNames.Jti)
                            ?.Value;

                        if (string.IsNullOrWhiteSpace(jti))
                        {
                            context.Fail(
                                "В токене отсутствует идентификатор.");
                            return;
                        }

                        var db = context.HttpContext.RequestServices
                            .GetRequiredService<AppDbContext>();

                        var isRevoked = await db.RevokedAccessTokens
                            .AsNoTracking()
                            .AnyAsync(x => x.Jti == jti);

                        if (isRevoked)
                        {
                            context.Fail("Токен отозван.");
                        }
                    }
                };
            });

        builder.Services.AddAuthorization();
        builder.Services.AddControllers();

        #endregion

        var app = builder.Build();

        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Database.Migrate();
        }

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();
        app.Run();
    }
}
