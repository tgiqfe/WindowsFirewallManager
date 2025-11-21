namespace WindowsFirewallManager
{
    internal class Logger
    {
        public static void WriteLine(LogLevel level, string title, string message) { }

        public static void WriteLine(string title, string message) { }

        public static void WriteLine(string level, string title, string message) { }

        public static void WriteRaw(string title, string message) { }
    }

    public enum LogLevel
    {
        None = 0,
        Debug = 1,
        Info = 2,
        Attention = 3,
        Warning = 4,
        Error = 5,
    }
}
