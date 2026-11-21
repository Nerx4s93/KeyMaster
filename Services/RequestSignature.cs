using System.Security.Cryptography;
using System.Text;

namespace KeyMaster.Services;

public static class RequestSignature
{
    public static byte[] Compute(
        string method,
        string path,
        string query,
        string body,
        string token)
    {
        var payload = $"{method}\n{path}\n{query}\n{body}";
        var data = Encoding.UTF8.GetBytes(payload + token);
        return SHA256.HashData(data);
    }
}
