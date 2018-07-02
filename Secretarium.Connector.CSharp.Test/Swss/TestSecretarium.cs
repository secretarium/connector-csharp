using Secretarium.Client.Helpers;
using NUnit.Framework;
using System.Threading;
using System.Security.Cryptography;

namespace Secretarium.Client.Test
{
    [TestFixture]
    public class TestSecretarium
    {
        [Test, Explicit]
        public void TestFullProtocolFromX509()
        {
            var maxWait = 200000;
            var signal = new AutoResetEvent(false);
            byte[] msg = null;
            Assert.IsTrue(SwssConfigHelper.TryLoad("test.json", out SwssConfig config));
            Assert.IsTrue(config.client.TryGetECDsaKey(out ECDsaCng clientECDsa));

            using (var swss = new SwssConnector())
            {
                swss.Init(config);
                swss.Set(clientECDsa);

                swss.OnMessage += x =>
                {
                    var res = x.ParseMessage();
                    if (!string.IsNullOrEmpty(res.requestId) && string.IsNullOrEmpty(res.error) && string.IsNullOrEmpty(res.state))
                    {
                        msg = x;
                        signal.Set();
                    }
                };

                var connected = swss.Connect();
                Assert.IsTrue(connected);

                var sumReqId = swss.Send("DCAppForTesting", "Sum", new double[] { 1, 2, 3, 4, 5 });

                var onTime = signal.WaitOne(maxWait);
                Assert.IsTrue(onTime);

                var sum = msg.ParseMessage<double>();
                Assert.AreEqual(15d, sum.result);

                var avgRewId = swss.Send("DCAppForTesting", "Avg", new double[] { 1, 2, 3, 4, 5 });
                onTime = signal.WaitOne(maxWait);
                Assert.IsTrue(onTime);

                var avg = msg.ParseMessage<double>();
                Assert.AreEqual(3d, avg.result);
            }
        }
    }
}
