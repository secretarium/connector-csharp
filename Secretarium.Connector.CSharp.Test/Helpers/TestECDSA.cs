using Secretarium.Helpers;
using NUnit.Framework;

namespace Secretarium.Test
{
    [TestFixture]
    public class TestECDSA
    {
        [Test]
        public void TestECDSAImportExport()
        {
            var key = ECDsaHelper.CreateECDsaCng256();
            var expPubKey = key.ExportPublicKeyRaw();

            var impPubKey = ECDsaHelper.ImportPublicKey(expPubKey);
            Assert.NotNull(impPubKey);

            var expPriKey = key.ExportPrivateKeyRaw();
            var impPriKey = ECDsaHelper.ImportPrivateKey(expPubKey, expPriKey);
            Assert.NotNull(impPriKey);
        }
    }
}