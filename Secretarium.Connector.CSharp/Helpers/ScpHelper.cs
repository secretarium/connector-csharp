namespace Secretarium.Helpers
{
    public static class ScpHelper
    {
        public static bool IsClosed(this SecureConnectionProtocol.ConnectionState state)
        {
            return state == SecureConnectionProtocol.ConnectionState.None || state == SecureConnectionProtocol.ConnectionState.Closed;
        }
    }
}