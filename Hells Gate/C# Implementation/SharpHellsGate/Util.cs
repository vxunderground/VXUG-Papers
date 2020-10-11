using System;
using System.Diagnostics;

namespace SharpHellsGate {

    /// <summary>
    /// Util class. Used mainly for debug output.
    /// </summary>
    public class Util {

        /// <summary>
        /// Structure used to store the name, address, system call and hash of a native Windows function.
        /// </summary>
        public struct APITableEntry {
            public string Name;
            public Int64 Address;
            public Int16 Syscall;
            public UInt64 Hash;
        }

        /// <summary>
        /// DJB2 Hash of the NtAllocateVirtualMemory function name.
        /// </summary>
        public static UInt64 NtAllocateVirtualMemoryHash { get; } = 0xf5bd373480a6b89b;

        /// <summary>
        /// DJB2 Hash of the NtProtectVirtualMemory function name.
        /// </summary>
        public static UInt64 NtProtectVirtualMemoryHash { get; } = 0x858bcb1046fb6a37;

        /// <summary>
        /// DJB2 Hash of the NtCreateThreadEx function name.
        /// </summary>
        public static UInt64 NtCreateThreadExHash { get; } = 0x64dc7db288c5015f;

        /// <summary>
        /// DJB2 Hash of the NtWaitForSingleObject function name.
        /// </summary>
        public static UInt64 NtWaitForSingleObjectHash { get; } = 0xc6a2fa174e551bcb;


        /// <summary>
        /// Log an informational information.
        /// </summary>
        /// <param name="msg">Message to log.</param>
        /// <param name="indent">Indentation level.</param>
        /// <param name="prefix">Message prefix.</param>
        public static void LogInfo(string msg, int indent = 0, string prefix = "[>]") {
#if DEBUG
            if (string.IsNullOrEmpty(msg))
                return;

            LogMessage(msg, prefix, indent, ConsoleColor.Blue);
#endif
        }

        /// <summary>
        /// Log an error information.
        /// </summary>
        /// <param name="msg">Message to log.</param>
        /// <param name="indent">Indentation level.</param>
        /// <param name="prefix">Message prefix.</param>
        public static void LogError(string msg, int indent = 0, string prefix = "[-]") {
#if DEBUG
            if (string.IsNullOrEmpty(msg))
                return;

            LogMessage(msg, prefix, indent, ConsoleColor.Red);
#endif
        }

        /// <summary>
        /// Log a success information.
        /// </summary>
        /// <param name="msg">Message to log.</param>
        /// <param name="indent">Indentation level.</param>
        /// <param name="prefix">Message prefix</param>
        public static void LogSuccess(string msg, int indent = 0, string prefix = "[+]") {
#if DEBUG
            if (string.IsNullOrEmpty(msg))
                return;

            LogMessage(msg, prefix, indent, ConsoleColor.Green);
#endif
        }

        /// <summary>
        /// Log a string to the console and to the debugger. 
        /// </summary>
        /// <param name="msg">Message to log.</param>
        /// <param name="indent">Indentation level.</param>
        /// <param name="prefix">Message prefix.</param>
        /// <param name="color">The color of the prifix on the console.</param>
        private static void LogMessage(string msg, string prefix, int indent, ConsoleColor color) {
            // Indent
            Console.Write(new String(' ', indent));
            Trace.Write(new String(' ', indent));

            // Color and prefix
            Trace.Write(prefix);
            Console.ForegroundColor = color;
            Console.Write(prefix);
            Console.ResetColor();

            // Message
            Console.WriteLine($" {msg}");
            Trace.WriteLine($" {msg}");
        }


        /// <summary>
        /// Revisited DJB2 algorithm.
        /// </summary>
        /// <param name="FunctionName">The ASCII name of a function.</param>
        /// <returns>The djb2 hash of the function name.</returns>
        public static UInt64 GetFunctionDJB2Hash(string FunctionName) {
            if (string.IsNullOrEmpty(FunctionName))
                return 0;

            UInt64 hash = 0x7734773477347734;
            foreach (char c in FunctionName)
                hash = ((hash << 0x5) + hash) + (byte)c;

            return hash;
        }

    }
}
