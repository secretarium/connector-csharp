using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Secretarium.Client.Helpers
{
    public static class SwssConfigHelper
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

        public static bool TryLoad(string configPath, out SwssConfig config)
        {
            config = null;

            if (!File.Exists(configPath))
                configPath = Path.Combine(ConfigDir, configPath);
            if (!File.Exists(configPath))
                return false;


            config = JsonHelper.DeserializeJsonFromFileAs<SwssConfig>(configPath);

            return true;
        }

        public static bool TryGetECDsaKey(this SwssConfig.ClientConfig config, out ECDsaCng key)
        {
            key = null;

            if (config == null)
                return false;

            if (config.keys.TryGetECDsaKey(out key))
                return true;

            if (config.certificate.TryGetECDsaKey(out key))
                return true;

            return false;
        }

        public static bool TryGetECDsaKey(this SwssConfig.KeyConfig config, out ECDsaCng key)
        {
            key = null;

            if (config == null)
                return false;

            if (string.IsNullOrEmpty(config.publicKey) || string.IsNullOrEmpty(config.privateKey))
                return false;

            try
            {
                var imp = ECDsaHelper.Import(config.publicKey.FromBase64String(), config.privateKey.FromBase64String());
                if (imp != null && imp.HashAlgorithm == CngAlgorithm.Sha256 && imp.KeySize == 256)
                {
                    key = imp;
                    return true;
                }
            }
            catch (Exception) { }

            return false;
        }

        public static bool TryGetECDsaKey(this SwssConfig.CertificateConfig config, out ECDsaCng key)
        {
            key = null;

            if (config == null)
                return false;

            if (string.IsNullOrEmpty(config.pfxFile) || string.IsNullOrEmpty(config.password))
                return false;

            var pfxPath = config.pfxFile.Contains("/") || config.pfxFile.Contains("\\") ? config.pfxFile : Path.Combine(ConfigDir, config.pfxFile);
            if (!File.Exists(pfxPath))
                return false;

            try
            {
                var x509 = X509Helper.LoadX509FromFile(pfxPath, config.password);
                if (x509.GetECDsaPrivateKey() is ECDsaCng imp && imp.HashAlgorithm == CngAlgorithm.Sha256 && imp.KeySize == 256)
                {
                    key = imp;
                    return true;
                }
            }
            catch (Exception) { }

            return false;
        }
    }
}
