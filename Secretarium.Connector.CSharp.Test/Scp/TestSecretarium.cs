using Secretarium.Helpers;
using NUnit.Framework;
using System.Threading;
using System.Security.Cryptography;

namespace Secretarium.Test
{
    [TestFixture]
    public class TestSecretarium
    {
        [Test, Explicit]
        public void TestFullProtocolFromSecKey()
        {
            Assert.IsTrue(ScpConfigHelper.TryLoad("test.secKey.json", out ScpConfig config));
            Assert.IsTrue(config.keys.TryGetECDsaKey(out ECDsaCng clientECDsa));

            using (var scp = new SecureConnectionProtocol())
            {
                scp.Init(config);
                scp.Set(clientECDsa);

                var connected = scp.Connect(20000);
                Assert.IsTrue(connected);
            }
        }
    }
}
