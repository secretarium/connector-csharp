using Secretarium.Client.Helpers;
using NUnit.Framework;

namespace Secretarium.Client.Test
{
    [TestFixture]
    public class TestJson
    {
        [Test]
        public void TestJsonByteArrayIsBase64Encoded()
        {
            var rdm = new byte[] {1, 2, 3};
            var obj = new ClientHello { ephDHKey = rdm };

            var json = obj.ToJson();

            Assert.AreEqual("{\"ephDHKey\":\"" + rdm.ToBase64String() + "\"}", json);
        }
    }
}
