using System.Security.Cryptography;

namespace Secretarium.Helpers
{
    public static class HashHelper
    {
        public static readonly SHA256Cng Sha256 = new SHA256Cng();

        public static byte[] HashSha256(this byte[] a)
        {
            return Sha256.ComputeHash(a);
        }

        public static byte[] HashSha256(this string s)
        {
            return Sha256.ComputeHash(s.ToBytes());
        }

        public static byte[] HashSha256(this bool b)
        {
            return Sha256.ComputeHash((b ? "true" : "false").ToBytes());
        }

        public static byte[] HashSha256(this int i)
        {
            return Sha256.ComputeHash(i.ToString("N6").ToBytes());
        }

        public static byte[] HashSha256(this long l)
        {
            return Sha256.ComputeHash(l.ToString("N6").ToBytes());
        }

        public static byte[] HashSha256(this double d)
        {
            return Sha256.ComputeHash(d.ToString("N6").ToBytes());
        }
    }
}
