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
            Assert.AreEqual(true.HashSha256(), "tb6kG2xiP3wJ8b8k3K5Y66s8DN2QrZZrxDpFtEhn4Ss=");
            Assert.AreEqual(false.HashSha256(), "/LzxZZCN0YqeSff/J4EBdtuOn2O0NSITdBZkJFIk+Ko=");
        }
    }
}
