/**
* @file			bcdutil.c
* @author		Paul L. (@am0nsec)
* @version		1.0
* @brief        Modify boot configuration to enable safe mode, disable recovery and ignore all failure.
* @details
* @link			https://github.com/am0nsec/vx
* @copyright	This project has been released under the GNU Public License v3 license.
*/
#ifndef __BCDUTIL_H_GUARD__
#define __BCDUTIL_H_GUARD__

#pragma comment(lib, "ntdll")

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

/**
 * @brief GUID of the Windows Boot Manager Configuration within the Windows Registry: 9DEA862C-5CDD-4E70-ACC1-F32B344D4795
*/
static CONST GUID GUID_WINDOWS_BOOTMGR = { 0x9DEA862C, 0x5CDD, 0x4E70, {0xAC, 0xC1, 0xF3, 0x2B, 0x34, 0x4D, 0x47, 0x95} };

// Taken from https://www.geoffchappell.com/notes/windows/boot/bcd/elements.htm?tx=27

#define GUID_WINDOWS_BOOTMGR                        L"{9DEA862C-5CDD-4E70-ACC1-F32B344D4795}"
#define BCD_ELEMENTS                                L"Elements"
#define BCD_ELEMENT                                 L"Element"

#define BCDE_BOOTMGR_TYPE_DEFAULT_OBJECT            L"23000003"
#define BCDE_OSLOADER_TYPE_SAFEBOOT                 L"25000080"
#define BCDE_LIBRARY_TYPE_AUTO_RECOVERY_ENABLED     L"16000009"
#define BCDE_OSLOADER_TYPE_BOOT_STATUS_POLICY       L"250000E0"

#define STATUS_SUCCESS               0x00000000
#define STATUS_UNSUCCESSFUL          0xC0000001
#define STATUS_INTERNAL_ERROR        0xC00000E5
#define STATUS_BUFFER_TOO_SMALL      0xC0000023
#define STATUS_NO_MORE_ENTRIES       0x8000001A
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034

#define RETURN_ON_ERROR(ex) \
	if (!NT_SUCCESS(ex)) { return STATUS_UNSUCCESSFUL; }

#define EXIT_ON_ERROR(ex) \
	if (!NT_SUCCESS(ex)) { return EXIT_FAILURE; }

#define EXIT_ON_ERROREX(ex, code) \
	if (ex != code) { return EXIT_FAILURE; }

typedef enum _KEY_INFORMATION_CLASS {
	KeyBasicInformation,
	KeyNodeInformation,
	KeyFullInformation,
	KeyNameInformation,
	KeyCachedInformation,
	KeyFlagsInformation,
	KeyVirtualizationInformation,
	KeyHandleTagsInformation,
	KeyTrustInformation,
	KeyLayerInformation,
	MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	KeyValueLayerInformation,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION {
	LARGE_INTEGER LastWriteTime;
	ULONG         TitleIndex;
	ULONG         NameLength;
	WCHAR         Name[1];
} KEY_BASIC_INFORMATION, * PKEY_BASIC_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataLength;
	UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, * PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _SECURITY_DESCRIPTOREX {
	UCHAR Revision;
	UCHAR Sbz1;
	WORD  Control;
	PVOID Owner;
	PVOID Group;
	PACL  Sacl;
	PACL  Dacl;
} SECURITY_DESCRIPTOREX, * PSECURITY_DESCRIPTOREX;


extern NTSTATUS NtOpenKey(
	_Out_ PHANDLE            KeyHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes
);


extern NTSTATUS NtQueryValueKey(
	_In_  HANDLE                      KeyHandle,
	_In_  PUNICODE_STRING             ValueName,
	_In_  KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	_Out_ PVOID                       KeyValueInformation,
	_In_  ULONG                       Length,
	_Out_ PULONG                      ResultLength
);


extern NTSTATUS NtCreateKey(
	_Out_     PHANDLE            KeyHandle,
	_In_      ACCESS_MASK        DesiredAccess,
	_In_      POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_     ULONG              TitleIndex,
	_In_opt_  PUNICODE_STRING    Class,
	_In_      ULONG              CreateOptions,
	_Out_opt_ PULONG             Disposition
);


extern NTSTATUS NtEnumerateKey(
	_In_  HANDLE                KeyHandle,
	_In_  ULONG                 Index,
	_In_  KEY_INFORMATION_CLASS KeyInformationClass,
	_Out_ PVOID                 KeyInformation,
	_In_  ULONG                 Length,
	_Out_ PULONG                ResultLength
);


extern NTSTATUS NtOpenMutant(
	_Out_ PHANDLE            MutantHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes,
	_In_  BOOLEAN            InitialOwner
);


extern NTSTATUS NtSetValueKey(
	_In_     HANDLE          KeyHandle,
	_In_     PUNICODE_STRING ValueName,
	_In_opt_ ULONG           TitleIndex,
	_In_     ULONG           Type,
	_In_     PVOID           Data,
	_In_     ULONG           DataSize
);


/**
 * @brief Get handle to the default Windows Boot Object.
 * @param phWindowsBootMgrDefaultObj Pointer to an handle.
 * @return Whether an handle has been successfully retrieved.
*/
_Success_(return == S_OK) _Must_inspect_result_ NTSTATUS
BcdGetDefaultBootObject(
	_Out_ PHKEY  phWindowsBootMgrDefaultObj
);


/**
 * @brief Modify boot configuration.
 * @param phKey Pointer to an handle of the Windows default boot object.
 * @param wszKey Name of the configuration to change.
 * @param pData Pointer to the data of the value.
 * @param ulData Size of the data for the value.
 * @return Whether boot configuration has been modified.
*/
_Success_(return == S_OK) _Must_inspect_result_ NTSTATUS
BcdModifyBootConfiguration(
	_In_ CONST PHKEY  phKey,
	_In_ CONST LPWSTR wszKey,
	_In_ LPVOID       pData,
	_In_ ULONG        ulData
);


/**
 * @brief Acquire an handle to the BCD synchronisation mutant.
 * @param phHandle Pointer to an handle.
 * @return Whether an handle to the BCD synchronisation mutant has been acquired.
*/
_Success_(return == S_OK) _Must_inspect_result_ NTSTATUS
BcdAcquireSyncMutant(
	_Out_ PHANDLE phHandle
);


/**
 * @brief Open an HANDLE to a registry object by name.
 * @param wszKeyName The Unicode name of the registry object.
 * @param AccessMask The desired access mask.
 * @param phDirectory Pointer to a parent object within the object manager namespace.
 * @param phKey Pointer to the HANDLE if found and successfully opened.
 * @return Whether the HANDLE has been open.
*/
_Success_(return == S_OK) _Must_inspect_result_ NTSTATUS
BcdOpenKeyByName(
	_In_  CONST LPWSTR wszKeyName,
	_In_  ACCESS_MASK  AccessMask,
	_In_  PHANDLE      phDirectory,
	_Out_ PHKEY        phKey
);


/**
 * @brief Find a sub key for a given pattern.
 * @param phKey Pointer to the key to search from.
 * @param wszPattern The pattern to find (e.g., BCD).
 * @param dwPatternLength Length of the pattern (e.g., 3).
 * @param wszSubKeyName Pointer to the name of the sub-key once found.
 * @param pdwSubKeyNameLength Pointer to the length of the sub-key once found.
 * @return Whether the sub-key has been found.
*/
_Success_(return == S_OK) _Must_inspect_result_ NTSTATUS
BcdpGetSubKeyByPattern(
	_In_  CONST PHKEY  phKey,
	_In_  CONST LPWSTR wszPattern,
	_In_  CONST DWORD  dwPatternLength,
	_Out_ LPWSTR * wszSubKeyName,
	_Out_ PDWORD       pdwSubKeyNameLength
);


/**
 * @brief Get the value of a Windows registry key by name.
 * @param wszValueName The Unicode name of the value to retrieve.
 * @param phKey Pointer to an handle of a Windows Registry key.
 * @param dwType Type of data to retreive.
 * @param ppData Pointer to a buffer.
 * @param pdwData Poitner to the size of the buffer that will be returned.
 * @return Whether the value has been successfully retrieved.
*/
_Success_(return == S_OK) _Must_inspect_result_ NTSTATUS
BcdpQueryValueByName(
	_In_  CONST LPWSTR wszValueName,
	_In_  PHKEY        phKey,
	_In_  DWORD        dwType,
	_Out_ LPVOID * ppData,
	_Out_ DWORD * pdwData
);


/**
 * @brief Create a new windows registry key.
 * @param wszKeyName The Unicode name of the key to create.
 * @param DesiredAccess Desired access.
 * @param dwType Type of data to retreive.
 * @param phDirectory Pointer to a parent object within the object manager namespace.
 * @param phKey Pointer to an handle of the newly created key.
 * @return Whether the key has been created.
*/
_Success_(return == S_OK) _Must_inspect_result_ NTSTATUS
BcdpCreateKey(
	_In_  CONST LPWSTR wszKeyName,
	_In_  ACCESS_MASK  DesiredAccess,
	_In_  PHANDLE      phDirectory,
	_Out_ PHANDLE      phKey
);


/**
 * @brief Set a new value to a windows registry key
 * @param wszKeyName The Unicode name of the value to create/modify.
 * @param phKey Handle to a windows registry key.
 * @param pData Pointer to the data of the value.
 * @param ulData Size of the data of the value.
 * @return Whether the value has been successfully created or modified.
*/
_Success_(return == S_OK) _Must_inspect_result_ NTSTATUS
BcdpSetValue(
	_In_ CONST LPWSTR wszValue,
	_In_ PHANDLE      phKey,
	_In_ PVOID        pData,
	_In_ ULONG        ulData
);


/**
 * @brief Set a new value to a windows registry key
 * @param phKey Handle to a windows registry key.
 * @param dwPrivileges Desried new privileges.
 * @return Whether the new privileges have been assigned
*/
_Success_(return == S_OK) _Must_inspect_result_ NTSTATUS
BcdpChangeObjectPermission(
	_In_ CONST PHANDLE phKey,
	_In_ DWORD         dwPrivileges
);


#endif // !__BCDUTIL_H_GUARD__
