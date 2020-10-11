using System;

namespace SharpHellsGate.Win32 {

    /// <summary>
    /// Windows Macros used for error and success codes and bitmasks.
    /// </summary>
    public static class Macros {

        // NTSTATUS 
        public static bool NT_SUCCESS(UInt32 ntstatus) => ntstatus <= 0x3FFFFFFF;
        public static bool NT_INFORMATION(UInt32 ntstatus) => ntstatus >= 0x40000000 && ntstatus <= 0x7FFFFFFF;
        public static bool NT_WARNING(UInt32 ntstatus) => ntstatus >= 0x80000000 && ntstatus <= 0xBFFFFFFF;
        public static bool NT_ERROR(UInt32 ntstatus) => ntstatus >= 0xC0000000 && ntstatus <= 0xFFFFFFFF;

        // Common NTSTATUS
        public static UInt32 STATUS_SUCCESS { get; } = 0x00000000;
        public static UInt32 STATUS_UNSUCCESSFUL { get; } = 0xC0000001;
        public static UInt32 STATUS_NOT_IMPLEMENTED { get; } = 0xC0000002;

        // Portable Executable
        public static Int16 IMAGE_DOS_SIGNATURE { get; } = 0x5a00 | 0x4D;          // MZ
        public static Int32 IMAGE_NT_SIGNATURE { get; } = 0x00004500 | 0x00000050; // PE00

        // Pseudo-Handles
        public static IntPtr GetCurrentProcess() => new IntPtr(-1);
        public static IntPtr GetCurrentThread() => new IntPtr(-2);
        public static IntPtr GetCurrentProcessToken() => new IntPtr(-4);
        public static IntPtr GetCurrentThreadToken() => new IntPtr(-5);
        public static IntPtr GetCurrentThreadEffectiveToken() => new IntPtr(-6);

        // Page and Memory permissions
        public static UInt32 PAGE_NOACCESS { get; } = 0x01;
        public static UInt32 PAGE_READONLY { get; } = 0x02;
        public static UInt32 PAGE_READWRITE { get; } = 0x04;
        public static UInt32 PAGE_WRITECOPY { get; } = 0x08;
        public static UInt32 PAGE_EXECUTE { get; } = 0x10;
        public static UInt32 PAGE_EXECUTE_READ { get; } = 0x20;
        public static UInt32 PAGE_EXECUTE_READWRITE { get; } = 0x40;
        public static UInt32 PAGE_EXECUTE_WRITECOPY { get; } = 0x80;
        public static UInt32 PAGE_GUARD { get; } = 0x100;
        public static UInt32 PAGE_NOCACHE { get; } = 0x200;    
        public static UInt32 PAGE_WRITECOMBINE { get; } = 0x400;  
        public static UInt32 PAGE_GRAPHICS_NOACCESS { get; } = 0x0800;
        public static UInt32 PAGE_GRAPHICS_READONLY { get; } = 0x1000;
        public static UInt32 PAGE_GRAPHICS_READWRITE { get; } = 0x2000;
        public static UInt32 PAGE_GRAPHICS_EXECUTE { get; } = 0x4000;
        public static UInt32 PAGE_GRAPHICS_EXECUTE_READ { get; } = 0x8000;
        public static UInt32 PAGE_GRAPHICS_EXECUTE_READWRITE { get; } = 0x10000;
        public static UInt32 PAGE_GRAPHICS_COHERENT { get; } = 0x20000;
        public static UInt32 PAGE_ENCLAVE_THREAD_CONTROL { get; } = 0x80000000;
        public static UInt32 PAGE_REVERT_TO_FILE_MAP { get; } = 0x80000000;
        public static UInt32 PAGE_TARGETS_NO_UPDATE { get; } = 0x40000000;
        public static UInt32 PAGE_TARGETS_INVALID { get; } = 0x40000000;
        public static UInt32 PAGE_ENCLAVE_UNVALIDATED { get; } = 0x20000000;
        public static UInt32 PAGE_ENCLAVE_DECOMMIT { get; } = 0x10000000;
        public static UInt32 MEM_COMMIT { get; } = 0x00001000;
        public static UInt32 MEM_RESERVE { get; } = 0x00002000;
        public static UInt32 MEM_REPLACE_PLACEHOLDER { get; } = 0x00004000;
        public static UInt32 MEM_RESERVE_PLACEHOLDER { get; } = 0x00040000; 
        public static UInt32 MEM_RESET { get; } = 0x00080000  ;
        public static UInt32 MEM_TOP_DOWN { get; } = 0x00100000;
        public static UInt32 MEM_WRITE_WATCH { get; } = 0x00200000;
        public static UInt32 MEM_PHYSICAL { get; } = 0x00400000;
        public static UInt32 MEM_ROTATE { get; } = 0x00800000;
        public static UInt32 MEM_DIFFERENT_IMAGE_BASE_OK { get; } = 0x00800000;
        public static UInt32 MEM_RESET_UNDO { get; } = 0x01000000;
        public static UInt32 MEM_LARGE_PAGES { get; } = 0x20000000;
        public static UInt32 MEM_4MB_PAGES { get; } = 0x80000000;
        public static UInt32 MEM_64K_PAGES { get; } = (MEM_LARGE_PAGES | MEM_PHYSICAL);
        public static UInt32 MEM_UNMAP_WITH_TRANSIENT_BOOST { get; } = 0x00000001; 
        public static UInt32 MEM_COALESCE_PLACEHOLDERS { get; } = 0x00000001; 
        public static UInt32 MEM_PRESERVE_PLACEHOLDER { get; } = 0x00000002;
        public static UInt32 MEM_DECOMMIT { get; } = 0x00004000;
        public static UInt32 MEM_RELEASE { get; } = 0x00008000;
        public static UInt32 MEM_FREE { get; } = 0x00010000;
    }
}
