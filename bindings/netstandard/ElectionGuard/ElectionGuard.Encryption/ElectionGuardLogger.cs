using System;
using System.IO;
using System.Runtime.InteropServices;

namespace ElectionGuard
{
    /// <summary>
    /// Log level enumeration for ElectionGuard native logging
    /// </summary>
    public enum LogLevel
    {
        Trace = 0,
        Debug = 1,
        Info = 2,
        Warn = 3,
        Error = 4,
        Critical = 5,
        Off = 6
    }

    /// <summary>
    /// Simple static class for configuring ElectionGuard native logging.
    /// Call once at application startup to configure where logs should be written.
    /// </summary>
    public static class ElectionGuardLog
    {
        private const string DllName = NativeInterface.DllName;

        [DllImport(DllName, EntryPoint = "eg_log_set_file", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int SetFileNative([MarshalAs(UnmanagedType.LPStr)] string filepath);

        [DllImport(DllName, EntryPoint = "eg_log_set_level", CallingConvention = CallingConvention.Cdecl)]
        private static extern int SetLevelNative(LogLevel level);

        /// <summary>
        /// Configure ElectionGuard to log to the specified file.
        /// All native ElectionGuard operations will automatically log to this file.
        /// Call this once at application startup.
        /// </summary>
        /// <param name="logFilePath">Full path to the log file</param>
        /// <param name="level">Minimum log level (default: Info)</param>
        public static void ConfigureLogging(string logFilePath, LogLevel level = LogLevel.Info)
        {
            if (string.IsNullOrEmpty(logFilePath))
                throw new ArgumentNullException(nameof(logFilePath));

            // Ensure directory exists
            var directory = Path.GetDirectoryName(logFilePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // Set log level
            var levelStatus = SetLevelNative(level);
            if (levelStatus != 0)
            {
                throw new InvalidOperationException($"Failed to set log level: {levelStatus}");
            }

            // Set log file
            var fileStatus = SetFileNative(logFilePath);
            if (fileStatus != 0)
            {
                throw new InvalidOperationException($"Failed to set log file: {fileStatus}");
            }
        }

        /// <summary>
        /// Set the minimum log level.
        /// Only messages at or above this level will be logged.
        /// </summary>
        public static void SetLogLevel(LogLevel level)
        {
            var status = SetLevelNative(level);
            if (status != 0)
            {
                throw new InvalidOperationException($"Failed to set log level: {status}");
            }
        }

        /// <summary>
        /// Get the default log file path for the current platform.
        /// Typically: %LocalAppData%\ElectionGuard\Logs\[filename]
        /// </summary>
        public static string GetDefaultLogPath(string fileName = "electionguard.log")
        {
            var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var logDir = Path.Combine(appDataPath, "ElectionGuard", "Logs");
            return Path.Combine(logDir, fileName);
        }
    }
}
