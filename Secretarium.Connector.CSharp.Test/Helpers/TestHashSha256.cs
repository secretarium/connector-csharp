using Secretarium.Helpers;
using NUnit.Framework;

namespace Secretarium.Test
{
    [TestFixture]
    public class TestHashSha256
    {
        [Test]
        public void TestHash()
        {
            var h = true.HashSha256().ToBase64String(false);
            Assert.AreEqual(h, "tb6kG2xiP3wJ8b8k3K5Y66s8DN2QrZZrxDpFtEhn4Ss=");

            h = false.HashSha256().ToBase64String(false);
            Assert.AreEqual(h, "/LzxZZCN0YqeSff/J4EBdtuOn2O0NSITdBZkJFIk+Ko=");
        }
    }
}
