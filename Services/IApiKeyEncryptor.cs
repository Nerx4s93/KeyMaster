namespace KeyMaster.Services;

public interface IApiKeyEncryptor
{
    string Encrypt(string plaintext);
    string Decrypt(string payload);
}
