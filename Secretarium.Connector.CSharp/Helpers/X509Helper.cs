using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Secretarium.Helpers
{
    public static class X509Helper
    {
        public static X509Certificate2 LoadX509FromFile(string fileFullName, string password)
        {
            return new X509Certificate2(fileFullName, password, X509KeyStorageFlags.Exportable);
        }

        public static X509Certificate2 ToPfx(this X509Certificate2 x509, string password)
        {
            return new X509Certificate2(x509.Export(X509ContentType.Pfx, password));
        }

        public static bool ToSecretariumKey(this X509Certificate2 x509, string password, out ScpConfig.SecretariumKeyConfig config)
        {
            config = null;

            var publicKey = x509.GetECDsaPublicKey() as ECDsaCng;
            if (publicKey == null)
                return false;
            if (publicKey.HashAlgorithm != CngAlgorithm.Sha256 || publicKey.KeySize != 256 || publicKey.Key.Algorithm != CngAlgorithm.ECDsaP256)
                return false;
            var publicKeyRaw = publicKey.ExportPublicKeyRaw();
            if (publicKeyRaw == null)
                return false;

            var privateKey = x509.GetECDsaPrivateKey() as ECDsaCng;
            if (privateKey == null)
                return false;
            var privatKeyRaw = privateKey.ExportPrivateKeyRaw();
            if (privatKeyRaw == null)
                return false;

            // Built pkcs8 manually because privateKey.Key.ForceExport(CngKeyBlobFormat.Pkcs8PrivateBlob) return 165 bytes instead of 138. TODO investigate
            var privatKeyPkcs8 = ByteHelper.Combine(
                new byte[] { 48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32 },
                privatKeyRaw,
                new byte[] { 161, 68, 3, 66, 0, 4 },
                publicKeyRaw
            );

            var salt = ByteHelper.GetRandom(32);
            var iv = ByteHelper.GetRandom(12);
            var strongPwd = ByteHelper.Combine(salt, password.ToBytes()).HashSha256();
            var keys = ByteHelper.Combine(new byte[] { 4 }, publicKeyRaw, privatKeyPkcs8);
            var encryptedKeys = AESGCMHelper.AesGcmEncrypt(keys, strongPwd, iv);

            config = new ScpConfig.SecretariumKeyConfig
            {
                iv = iv.ToBase64String(false),
                salt = salt.ToBase64String(false),
                keys = encryptedKeys.ToBase64String(false)
            };

            return true;
        }
    }
}
