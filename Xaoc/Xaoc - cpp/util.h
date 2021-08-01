/**
* @file        util.h
* @date        05/07/2021
* @author      Paul L. (@am0nsec)
* @version     1.0
* @brief
* @details
* @link
* @copyright   This project has been released under the GNU Public License v3 license.
*/
#ifndef __UTIL_H_GUARD__
#define __UTIL_H_GUARD__

#include <Windows.h>

#define EXIT_ON_FAILURE(exp) \
	if (FAILED(exp)) { return EXIT_FAILURE; } 

#define THROW_ON_FAILURE(exp) \
	if (FAILED(exp)) { return E_FAIL; } 

/**
 * @brief Ensure that the token has the SeBackupPrivilege privilege.
 * @return Wether the token has the SeBackupPrivilege privilege.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT AssertPrivilege(VOID) {

	// 1. Get handle to the token object.
	HANDLE hProcess = (HANDLE) -1;
	HANDLE hToken = INVALID_HANDLE_VALUE;
	OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (hToken == INVALID_HANDLE_VALUE)
		return E_FAIL;

	// 2. Adjust the token privileges if required.
	TOKEN_PRIVILEGES TokenPrivileges = { 0x00 };
	DWORD dwTokenLenght = 0x00;
	LUID LocalIdentifier = { 0x00 };


	if (LookupPrivilegeValueW(NULL, L"SeBackupPrivilege", &LocalIdentifier)) {
		TokenPrivileges.Privileges[0x0].Luid = LocalIdentifier;
		TokenPrivileges.Privileges[0x00].Attributes = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED;
		TokenPrivileges.PrivilegeCount = 0x01;

		if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, 0x00, NULL, &dwTokenLenght)) {
			CloseHandle(hToken);
			return E_FAIL;
		}
	}

	// 3. Close handle and return.
	CloseHandle(hToken);
	return S_OK;
}

/**
 * @brief Initialise the process to be able to use various COM servers.
 * @return Whether the process has been successfully initialised.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT InitialiseProcess() {
	// 1. Initialise COM context
	THROW_ON_FAILURE(CoInitializeEx(NULL, 0x00));
	THROW_ON_FAILURE(CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IDENTIFY,
		NULL,
		EOAC_NONE,
		NULL
	));

	// 2. Disable SEH
	IGlobalOptions* pIGlobalOptions = NULL;
	THROW_ON_FAILURE(CoCreateInstance(
		&CLSID_GlobalOptions,
		NULL,
		CLSCTX_INPROC_SERVER,
		&IID_IGlobalOptions,
		(LPVOID*)&pIGlobalOptions
	));
	THROW_ON_FAILURE(pIGlobalOptions->lpVtbl->Set(
		pIGlobalOptions,
		COMGLB_EXCEPTION_HANDLING,
		COMGLB_EXCEPTION_DONOT_HANDLE
	));
	pIGlobalOptions->lpVtbl->Release(pIGlobalOptions);

	return S_OK;
}

#endif // !__UTIL_H_GUARD__
