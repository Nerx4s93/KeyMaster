using System.Security.Cryptography;
using System.Text;

namespace KeyMaster.Services;

public static class RequestSignature
{
    public static byte[] Compute(string payload, string token)
    {
        var data = Encoding.UTF8.GetBytes(payload + token);
        return SHA256.HashData(data);
    }
}
