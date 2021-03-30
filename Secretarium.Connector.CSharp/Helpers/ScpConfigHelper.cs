using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Secretarium.Helpers
{
    public static class ScpConfigHelper
    {
        private static string _configDir;

        public static string ConfigDir
        {
            get
            {
                if (_configDir != null) return _configDir;

                var currentDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                if (currentDir == null) return "";

                var configDir = Path.Combine(currentDir, "Config");
                if(Directory.Exists(configDir))
                    return (_configDir = configDir);

                return (_configDir = currentDir);
            }
        }

        public static bool TryLoad(string configPath, out ScpConfig config)
        {
            config = null;

            if (!File.Exists(configPath))
                configPath = Path.Combine(ConfigDir, configPath);
            if (!File.Exists(configPath))
                return false;


            config = JsonHelper.DeserializeJsonFromFileAs<ScpConfig>(configPath);

            return true;
        }

        public static bool TryGetECDsaKeys(this ScpConfig.SecretariumKeyConfig config, string password, out byte[] publicKeyRaw, out byte[] privateKeyRaw)
        {
            publicKeyRaw = null;
            privateKeyRaw = null;

            if (config == null)
                return false;

            if (string.IsNullOrEmpty(config.keys))
                return false;

            byte[] keys = config.keys.FromBase64String();

            if (!string.IsNullOrEmpty(config.iv) && !string.IsNullOrEmpty(config.salt) && !string.IsNullOrEmpty(password)) // encrypted
            {
                var iv = config.iv.FromBase64String();
                if (iv.Length != 12)
                    return false;

                var salt = config.salt.FromBase64String();
                if (salt.Length != 32)
                    return false;

                var strongPwd = ByteHelper.Combine(salt, password.ToBytes()).HashSha256();
                try
                {
                    keys = AESGCMHelper.AesGcmDecrypt(keys, strongPwd, iv);
                }
                catch (Exception)
                {
                    return false;
                }
            }

            if (string.IsNullOrEmpty(config.version)) // raw + pkcs8
            {
                if (keys.Length != 1 + 64 + 36 + 32 + 6 + 64) // 65 bytes uncompressed raw pub key + 138 bytes pkcs8 pri key
                    return false;

                publicKeyRaw = keys.Extract(1, 64);
                privateKeyRaw = keys.Extract(65 + 36, 32);
            }
            else if (config.version == "1") // jwt
            {
                // TODO: parse jwt
                return false;
            }

            return true;
        }
        public static bool TryGetECDsaKeys(this ScpConfig.RawKeyConfig config, out byte[] publicKeyRaw, out byte[] privateKeyRaw)
        {
            publicKeyRaw = null;
            privateKeyRaw = null;

            if (config == null || string.IsNullOrEmpty(config.publicKey) || string.IsNullOrEmpty(config.privateKey))
                return false;

            publicKeyRaw = config.publicKey.FromBase64String();
            privateKeyRaw = config.privateKey.FromBase64String();

            return true;
        }
        public static bool TryGetECDsaKeys(this ScpConfig.Certificate config, string password, out byte[] publicKeyRaw, out byte[] privateKeyRaw)
        {
            publicKeyRaw = null;
            privateKeyRaw = null;

            if (config == null || !config.TryGetX509(password, out X509Certificate2 x509))
                return false;

            try
            {
                var publicKey = x509.GetECDsaPublicKey() as ECDsaCng;
                if (publicKey == null)
                    return false;

                var privateKey = x509.GetECDsaPrivateKey() as ECDsaCng;
                if (privateKey == null)
                    return false;

                publicKeyRaw = publicKey.ExportPublicKeyRaw();
                privateKeyRaw = privateKey.ExportPrivateKeyRaw();
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }
        public static bool TryGetX509(this ScpConfig.Certificate config, string password, out X509Certificate2 x509)
        {
            x509 = null;

            if (config == null || string.IsNullOrEmpty(config.pfxFile))
                return false;

            var pfxPath = config.pfxFile.Contains("/") || config.pfxFile.Contains("\\") ? config.pfxFile : Path.Combine(ConfigDir, config.pfxFile);
            if (!File.Exists(pfxPath))
                return false;

            try
            {
                x509 = X509Helper.LoadX509FromFile(pfxPath, password);
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }

        public static bool TryGetECDsaKey(this ScpConfig config, out ECDsaCng key, string password = null)
        {
            key = null;

            if (config == null)
                return false;

            // -1- Secretarium Key file
            if (config.secretariumKey != null && config.secretariumKey.TryGetECDsaKeys(password, out byte[] publicKeyRaw, out byte[] privateKeyRaw))
            {
                try
                {
                    key = ECDsaHelper.ImportPrivateKey(publicKeyRaw, privateKeyRaw);
                }
                catch (Exception)
                {
                    return false;
                }
            }

            // -2- Certificate
            else if (config.certificate != null && config.certificate.TryGetX509(password, out X509Certificate2 x509))
            {
                try
                {
                    key = x509.GetECDsaPrivateKey() as ECDsaCng;
                }
                catch (Exception)
                {
                    return false;
                }
            }

            // -3- Raw keys
            else if (config.rawKeys != null && config.rawKeys.TryGetECDsaKeys(out publicKeyRaw, out privateKeyRaw))
            {
                try
                {
                    key = ECDsaHelper.ImportPrivateKey(publicKeyRaw, privateKeyRaw);
                }
                catch (Exception)
                {
                    return false;
                }
            }

            return key != null;
        }

        public static bool TryCreateSecretariumKey(string pfxFile, string password, out ScpConfig.SecretariumKeyConfig config)
        {
            config = null;

            var pfxConf = new ScpConfig.Certificate { pfxFile = pfxFile };
            if (!pfxConf.TryGetX509(password, out X509Certificate2 x509))
                return false;

            return x509.ToSecretariumKey(password, out config);
        }
    }
}
