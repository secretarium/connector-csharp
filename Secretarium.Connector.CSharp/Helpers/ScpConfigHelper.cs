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
        
        public static bool TryGetECDsaKey(this ScpConfig.KeyConfig config, out ECDsaCng key)
        {
            key = null;

            if (config == null)
                return false;

            // -1- Secretarium Key file
            if (!string.IsNullOrEmpty(config.iv) && !string.IsNullOrEmpty(config.salt) && !string.IsNullOrEmpty(config.keys) && !string.IsNullOrEmpty(config.password))
            {
                try
                {
                    var iv = config.iv.FromBase64String();
                    var salt = config.salt.FromBase64String();
                    var encryptedKeys = config.keys.FromBase64String();
                    var weakPwd = config.password.ToBytes();                    
                    var strongPwd = ByteHelper.Combine(salt, weakPwd).HashSha256();
                    var decryptedKeys = AESGCMHelper.AesGcmDecrypt(encryptedKeys, strongPwd, iv);
                    var publicKey = decryptedKeys.Extract(0, 65);
                    var imp = ECDsaHelper.Import(decryptedKeys.Extract(65));

                    key = imp;
                    return true;
                }
                catch (Exception) { }
            }
            
            // -2- Certificate
            else if (!string.IsNullOrEmpty(config.pfxFile) && !string.IsNullOrEmpty(config.password))
            {
                var pfxPath = config.pfxFile.Contains("/") || config.pfxFile.Contains("\\") ? config.pfxFile : Path.Combine(ConfigDir, config.pfxFile);
                if (File.Exists(pfxPath))
                {
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
                }
            }

            // -3- Private and public keys
            else if(!string.IsNullOrEmpty(config.publicKey) && !string.IsNullOrEmpty(config.privateKey))
            {
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
            }

            return false;
        }
    }
}
