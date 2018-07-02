using System.IO;
using Secretarium.Client.Helpers;
using Newtonsoft.Json;
using NUnit.Framework;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace Secretarium.Client.Test
{
    [TestFixture]
    public class TestX509
    {
        private X509Certificate2 _x509;

        [OneTimeSetUp]
        public void FixtureSetup()
        {
            var configDir = SwssConfigHelper.ConfigDir;
            Assert.NotNull(configDir, "can't find config dir");

            var config = JsonConvert.DeserializeObject<SwssConfig.CertificateConfig>(
                @"
                    {
                        ""password"": ""SecretariumTestClient256"",
                        ""pfxFile"": ""SecretariumTestClient256.pfx""
                    }"
            );
            Assert.NotNull(config, "can't parse config");

            var pfxPath = Path.Combine(configDir, config.pfxFile);
            Assert.IsTrue(File.Exists(pfxPath), "pfx file not found");

            _x509 = X509Helper.LoadX509FromFile(pfxPath, config.password);
            Assert.NotNull(_x509);
        }

        [Test]
        public void TestX509CanSign()
        {
            var publicKey = _x509.GetECDsaPublicKey();
            var privateKey = _x509.GetECDsaPrivateKey();

            var publicKeyCng = publicKey as ECDsaCng;
            Assert.NotNull(publicKeyCng);
            var privateKeyCng = privateKey as ECDsaCng;
            Assert.NotNull(privateKeyCng);

            var nonce = ByteHelper.GetRandom(96);
            var signed = privateKeyCng.SignData(nonce);

            Assert.IsTrue(publicKeyCng.VerifyData(nonce, signed));
        }
    }
}