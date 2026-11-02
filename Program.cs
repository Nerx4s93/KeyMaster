using DotNetEnv;
using KeyMaster.Options;
using KeyMaster.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;

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

        #region encryption

        builder.Services.AddSingleton<IApiKeyEncryptor, ApiKeyEncryptor>();

        #endregion

        #region authentication

        builder.Services
            .AddAuthentication(TokenAuthenticationHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, TokenAuthenticationHandler>(
                TokenAuthenticationHandler.SchemeName,
                null);

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
