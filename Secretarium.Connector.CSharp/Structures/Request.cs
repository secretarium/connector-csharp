using Secretarium.Helpers;
using System.Threading;

namespace Secretarium
{
    public abstract class RequestBase
    {
        public static long Counter = 0;

        public virtual string requestId { get; private set; }
        public string dcapp { get; private set; }
        public string function { get; private set; }

        public RequestBase(string dcapp, string function)
        {
            requestId = Interlocked.Increment(ref Counter).ToBytes().ToBase64String();
            this.dcapp = dcapp;
            this.function = function;
        }
    }

    public class Request : RequestBase
    {
        public string argsJson { get; private set; }

        public Request(string dcapp, string function, string argsJson) : base(dcapp, function)
        {
            this.argsJson = argsJson;
        }

        public string ToJson()
        {
            return "{\"requestId\":\"" + requestId + "\",\"dcapp\":\"" + dcapp + "\",\"function\":\"" + function + "\",\"args\":" + argsJson + "}";
        }
    }

    public class Request<T> : RequestBase where T : class
    {
        public T args { get; private set; }

        public Request(string dcapp, string function, T args) : base(dcapp, function)
        {
            this.args = args;
        }
    }
}