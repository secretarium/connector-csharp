using Secretarium.Helpers;
using System.Threading;

namespace Secretarium
{
    public class Request
    {
        public static long Counter = 0;

        public virtual string requestId { get; private set; }
        public string dcapp { get; private set; }
        public string function { get; private set; }

        public Request(string dcapp, string function)
        {
            requestId = Interlocked.Increment(ref Counter).ToBytes().ToBase64String();
            this.dcapp = dcapp;
            this.function = function;
        }
    }

    public class Request<T> : Request where T : class
    {
        public T args { get; private set; }

        public Request(string dcapp, string function, T args) : base(dcapp, function)
        {
            this.args = args;
        }
    }
}