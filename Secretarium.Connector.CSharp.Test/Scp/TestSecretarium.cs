using Secretarium.Helpers;
using NUnit.Framework;
using System.Security.Cryptography;

namespace Secretarium.Test
{
    [TestFixture]
    public class TestSecretarium
    {
        [Test, Explicit, Ignore("for debug only")]
        public void TestFullProtocolFromSecKeyCtr()
        {
            Assert.IsTrue(ScpConfigHelper.TryLoad("test.secKey.json", out ScpConfig config));
            Assert.IsTrue(config.secretariumKey.TryGetECDsaKeys("SecretariumTestClient256", out byte[] publicKeyRaw, out byte[] privateKeyRaw));

            var key = ECDsaHelper.ImportPrivateKey(publicKeyRaw, privateKeyRaw);
            Assert.NotNull(key);

            using (var scp = new SecureConnectionProtocol())
            {
                scp.Init(config);
                scp.Set(key);

                var connected = scp.Connect(20000);
                Assert.IsTrue(connected);
            }
        }

        [Test, Explicit, Ignore("for debug only")]
        public void TestFullProtocolFromSecKeyGcm()
        {
            Assert.IsTrue(ScpConfigHelper.TryLoad("test.secKey.json", out ScpConfig config));
            Assert.IsTrue(config.TryGetECDsaKey(out ECDsaCng key, "SecretariumTestClient256"));

            config.encryptionMode = ScpConfig.EncryptionMode.AESGCM;

            using (var scp = new SecureConnectionProtocol())
            {
                scp.Init(config);
                scp.Set(key);

                var connected = scp.Connect(20000);
                Assert.IsTrue(connected);
            }
        }
    }
}
