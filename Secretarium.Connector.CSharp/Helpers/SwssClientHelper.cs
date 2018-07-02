namespace Secretarium.Client.Helpers
{
    public static class SwssClientHelper
    {
        public static bool IsClosed(this SwssConnector.ConnectionState state)
        {
            return state == SwssConnector.ConnectionState.None || state == SwssConnector.ConnectionState.Closed;
        }
    }
}