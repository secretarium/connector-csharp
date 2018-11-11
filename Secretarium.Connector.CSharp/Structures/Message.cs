using Secretarium.Helpers;

namespace Secretarium
{
    public class Message
    {
        public string requestId { get; set; }
        public string error { get; set; }
        public string state { get; set; }
    }

    public class Result<T> : Message
    {
        public T result { get; set; }

        public static byte[] GetBytes(string requestId, T result)
        {
            return new Result<T> { requestId = requestId, result = result }.ToJson().ToBytes();
        }
    }
}