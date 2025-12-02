using Serilog;

namespace WT.Application.APIServiceLogs
{
    /// <summary>
    /// This class manages logging via Serilog.
    /// see: https://github.com/serilog/serilog-aspnetcore
    /// </summary>
    public static class LogException
    {
        public static void LogExceptions(Exception ex)
        {
            LogToFile(ex.Message);
            LogToConsole(ex.Message);
            LogToDebugger(ex.Message);
        }


        /// <summary>
        /// Log Information to a file
        /// </summary>
        /// <param name="message"></param>
        public static void LogToFile(string message) => Log.Information(message);
        /// <summary>
        /// Loging Warning to the Console
        /// </summary>
        /// <param name="message"></param>
        public static void LogToConsole(string message) => Log.Warning(message);
        /// <summary>
        /// Logging Debug information
        /// </summary>
        /// <param name="message"></param>
        public static void LogToDebugger(string message) => Log.Debug(message);
    }
}
