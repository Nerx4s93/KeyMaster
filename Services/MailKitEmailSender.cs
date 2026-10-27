using KeyMaster.Options;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace KeyMaster.Services;

public sealed class MailKitEmailSender : IEmailSender
{
    private readonly EmailOptions _options;

    public MailKitEmailSender(IOptions<EmailOptions> options)
    {
        _options = options.Value;
    }

    public async Task SendVerificationCodeAsync(
        string email,
        string code,
        CancellationToken cancellationToken = default)
    {
        var message = new MimeMessage();

        message.From.Add(new MailboxAddress(
            _options.FromName,
            _options.From));
        message.To.Add(MailboxAddress.Parse(email));
        message.Subject = "Подтверждение email";
        message.Body = new BodyBuilder
        {
            TextBody =
                $"Ваш код подтверждения: {code}\n\n" +
                "Код действителен 15 минут."
        }.ToMessageBody();

        using var smtp = new SmtpClient();

        var security = _options.UseSsl
            ? SecureSocketOptions.SslOnConnect
            : SecureSocketOptions.StartTls;

        await smtp.ConnectAsync(
            _options.Host,
            _options.Port,
            security,
            cancellationToken);

        await smtp.AuthenticateAsync(
            _options.UserName,
            _options.Password,
            cancellationToken);

        await smtp.SendAsync(message, cancellationToken);

        await smtp.DisconnectAsync(
            true,
            cancellationToken);
    }
}