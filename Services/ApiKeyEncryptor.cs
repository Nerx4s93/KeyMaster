using System.Security.Cryptography;
using System.Text;

namespace KeyMaster.Services;

public sealed class ApiKeyEncryptor : IApiKeyEncryptor
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly byte[] _key;

    public ApiKeyEncryptor(IConfiguration configuration)
    {
        var value = configuration["Encryption:Key"]
            ?? throw new InvalidOperationException(
                "Encryption:Key is not configured.");

        _key = Convert.FromBase64String(value.Trim());

        if (_key.Length != 32)
        {
            throw new InvalidOperationException(
                "Encryption:Key must be 32 bytes (Base64).");
        }
    }

    public string Encrypt(string plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var cipherBytes = new byte[plainBytes.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plainBytes, cipherBytes, tag);

        var payload = new byte[NonceSize + cipherBytes.Length + TagSize];
        Buffer.BlockCopy(nonce, 0, payload, 0, NonceSize);
        Buffer.BlockCopy(cipherBytes, 0, payload, NonceSize, cipherBytes.Length);
        Buffer.BlockCopy(tag, 0, payload, NonceSize + cipherBytes.Length, TagSize);

        return Convert.ToBase64String(payload);
    }

    public string Decrypt(string payload)
    {
        var data = Convert.FromBase64String(payload);

        if (data.Length < NonceSize + TagSize)
        {
            throw new CryptographicException("Некорректный шифротекст.");
        }

        var nonce = data.AsSpan(0, NonceSize);
        var cipherBytes = data.AsSpan(
            NonceSize,
            data.Length - NonceSize - TagSize);
        var tag = data.AsSpan(data.Length - TagSize, TagSize);
        var plainBytes = new byte[cipherBytes.Length];

        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(nonce, cipherBytes, tag, plainBytes);

        return Encoding.UTF8.GetString(plainBytes);
    }
}
