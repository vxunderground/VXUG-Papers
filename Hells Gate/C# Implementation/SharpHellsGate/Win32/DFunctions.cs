using System;
using System.Runtime.InteropServices;

namespace SharpHellsGate.Win32 {

    /// <summary>
    /// Contains all the delegates used to execute the system calls.
    /// </summary>
    public class DFunctions {

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
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            UInt32 AllocationType,
            UInt32 Protect
        );

        /// <summary>
        /// Managed wrapper around the NtProtectVirtualMemory native Windows function.
        /// </summary>
        /// <param name="ProcessHandle">Handle to Process Object opened with PROCESS_VM_OPERATION access.</param>
        /// <param name="BaseAddress">Pointer to base address to protect. Protection will change on all page containing specified address. On output, BaseAddress will point to page start address.</param>
        /// <param name="NumberOfBytesToProtect">Pointer to size of region to protect. On output will be round to page size (4KB).</param>
        /// <param name="NewAccessProtection">One or some of PAGE_... attributes.</param>
        /// <param name="OldAccessProtection">Receive previous protection.</param>
        /// <returns>NtProtectVirtualMemory returns either STATUS_SUCCESS or an error status code.</returns>
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            UInt32 NewProtect,
            out UInt32 OldProtect
        );

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
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtCreateThreadEx(
            ref IntPtr hThread,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            uint StackZeroBits,
            uint SizeOfStackCommit,
            uint SizeOfStackReserve,
            IntPtr lpBytesBuffer
        );

        /// <summary>
        /// Managed wrapper around the NtWaitForSingleObject native Windows function.
        /// </summary>
        /// <param name="ObjectHandle">Open handle to a alertable executive object.</param>
        /// <param name="Alertable">If set, calling thread is signaled, so all queued APC routines are executed.</param>
        /// <param name="TimeOuts">Time-out interval, in microseconds. NULL means infinite.</param>
        /// <returns>NtWaitForSingleObject returns either STATUS_SUCCESS or an error status code.</returns>
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWaitForSingleObject(
            IntPtr ObjectHandle,
            bool Alertable,
            ref Structures.LARGE_INTEGER TimeOut
        );
    }
}
