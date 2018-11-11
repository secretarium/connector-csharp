using Secretarium.Helpers;
using NUnit.Framework;
using System.Security.Cryptography;

namespace Secretarium.Test
{
    [TestFixture]
    public class TestScpConfig
    {
        private void SignAndVerify(ECDsaCng key)
        {
            var nonce = ByteHelper.GetRandom(32);
            var nonceSigned = key.SignData(nonce);

            var pubKey = key.Key.PublicKey();
            Assert.IsTrue(key.VerifyData(nonce, nonceSigned));
        }

        [Test]
        public void TestScpConfigECDSAFromX509()
        {
            Assert.IsTrue(ScpConfigHelper.TryLoad("test.x509.json", out ScpConfig config));
            Assert.IsTrue(config.keys.TryGetECDsaKey(out ECDsaCng key));
            SignAndVerify(key);
        }

        [Test]
        public void TestScpConfigECDSAFromSecKey()
        {
            Assert.IsTrue(ScpConfigHelper.TryLoad("test.secKey.json", out ScpConfig config));
            Assert.IsTrue(config.keys.TryGetECDsaKey(out ECDsaCng key));
            SignAndVerify(key);
        }
    }
}
