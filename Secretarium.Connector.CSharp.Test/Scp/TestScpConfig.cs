using Secretarium.Helpers;
using NUnit.Framework;
using Newtonsoft.Json;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace Secretarium.Test
{
    [TestFixture]
    public class TestScpConfig
    {
        private void SignAndVerify(byte[] publicKeyRaw, byte[] privateKeyRaw)
        {
            var privateKey = ECDsaHelper.ImportPrivateKey(publicKeyRaw, privateKeyRaw);
            Assert.NotNull(privateKey);

            var nonce = ByteHelper.GetRandom(32);
            var nonceSigned = privateKey.SignData(nonce);

            var publicKey = ECDsaHelper.ImportPublicKey(publicKeyRaw);
            Assert.NotNull(publicKey);
            Assert.IsTrue(publicKey.VerifyData(nonce, nonceSigned));
        }

        [Test]
        public void TestScpConfigECDSAFromX509()
        {
            Assert.IsTrue(ScpConfigHelper.TryLoad("test.x509.json", out ScpConfig config));
            Assert.IsTrue(config.certificate.TryGetECDsaKeys("SecretariumTestClient256", out byte[] publicKeyRaw, out byte[] privateKeyRaw));
            SignAndVerify(publicKeyRaw, privateKeyRaw);

            Assert.NotNull(config.certificate);
            Assert.IsTrue(config.certificate.TryGetX509("SecretariumTestClient256", out X509Certificate2 x509));
            Assert.NotNull(x509);

            var publicKey = x509.GetECDsaPublicKey() as ECDsaCng;
            Assert.NotNull(publicKey);
            var publicKeyRawCert = publicKey.ExportPublicKeyRaw();
            Assert.IsTrue(publicKeyRaw.SequenceEqual(publicKeyRawCert));

            var privateKey = x509.GetECDsaPrivateKey() as ECDsaCng;
            Assert.NotNull(privateKey);
            var privateKeyRawCert = privateKey.ExportPrivateKeyRaw();
            Assert.IsTrue(privateKeyRaw.SequenceEqual(privateKeyRawCert));

            SignAndVerify(publicKeyRawCert, privateKeyRawCert);
        }

        [Test]
        public void TestScpConfigECDSAFromSecKey()
        {
            Assert.IsTrue(ScpConfigHelper.TryLoad("test.secKey.json", out ScpConfig config));
            Assert.IsTrue(config.secretariumKey.TryGetECDsaKeys("SecretariumTestClient256", out byte[] publicKey, out byte[] privateKey));
            SignAndVerify(publicKey, privateKey);
        }

        [Test]
        public void TestScpConfigECDSAFromSecKey2()
        {
            Assert.IsTrue(ScpConfigHelper.TryLoad("test.secKey_2.json", out ScpConfig config));
            Assert.IsTrue(config.secretariumKey.TryGetECDsaKeys("1234", out byte[] publicKey, out byte[] privateKey));
            SignAndVerify(publicKey, privateKey);
        }

        [Test]
        public void TestX509ToSecKey()
        {
            Assert.IsTrue(ScpConfigHelper.TryCreateSecretariumKey("SecretariumTestClient256.pfx", "SecretariumTestClient256", out ScpConfig.SecretariumKeyConfig config));
            Assert.NotNull(config);

            var iv = config.iv.FromBase64String();
            var salt = config.salt.FromBase64String();
            var encryptedKeys = config.keys.FromBase64String();
            var strongPwd = ByteHelper.Combine(salt, "SecretariumTestClient256".ToBytes()).HashSha256();
            var decryptedKeys = AESGCMHelper.AesGcmDecrypt(encryptedKeys, strongPwd, iv);
            var pubKeyRaw = decryptedKeys.Extract(1, 64);
            var priKeyRaw = decryptedKeys.Extract(65 + 36, 32);
            var pubKeyRawFromPkcs8 = decryptedKeys.Extract(65 + 74, 64);
            Assert.IsTrue(pubKeyRaw.SequenceEqual(pubKeyRawFromPkcs8));
            Assert.IsTrue(EllipticCurveHelper.IsKeyOnP256(pubKeyRaw, true));
            SignAndVerify(pubKeyRaw, priKeyRaw);
        }
    }
}
