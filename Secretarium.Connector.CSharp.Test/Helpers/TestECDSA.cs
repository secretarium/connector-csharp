using Secretarium.Client.Helpers;
using NUnit.Framework;

namespace Secretarium.Client.Test
{
    [TestFixture]
    public class TestECDSA
    {
        [Test]
        public void TestECDSAImportExport()
        {
            var key = ECDsaHelper.CreateECDsaCng256();
            var expPubKey = key.PublicKey();
            var impKey = expPubKey.ToECDsaCngKey();
        }
    }
}