using System.Security.Cryptography.X509Certificates;

namespace Secretarium.Client.Helpers
{
    public static class X509Helper
    {
        public static X509Certificate2 LoadX509FromFile(string fileFullName, string password)
        {
            return new X509Certificate2(fileFullName, password, X509KeyStorageFlags.DefaultKeySet);
        }
    }
}
