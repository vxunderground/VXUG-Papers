; @file			  HELLSGATE.INC
; @data			  07-08-2020
; @author		  Paul Laîné (@am0nsec)
; @version		1.0
; @brief		  Dynamically extracting and invoking syscalls from in-memory modules.
; @details		
; @link			  https://ntamonsec.blogspot.com/
; @copyright	This project has been released under the GNU Public License v3 license.

VXTableEntrySize       EQU SIZEOF VX_TABLE_ENTRY
VXTableSize            EQU SIZEOF VX_TABLE

VX_TABLE_ENTRY struct
    pAddress    QWORD ?       ; 0x0000
    dwHash      DWORD ?       ; 0x0008
    wSystemCall WORD  ?       ; 0x000C
                BYTE 2 dup(?) ; padding
VX_TABLE_ENTRY ends

VX_TABLE struct
    NtAllocateVirtualMemory VX_TABLE_ENTRY <> ; 0x0000
    NtProtectVirtualMemory  VX_TABLE_ENTRY <> ; 0x0010
    NtCreateThreadEx        VX_TABLE_ENTRY <> ; 0x0020
    NtWaitForSingleObject   VX_TABLE_ENTRY <> ; 0x0030
VX_TABLE ends

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
    GdiDCAttributeList                  DWORD ?            ; 0x0108
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
