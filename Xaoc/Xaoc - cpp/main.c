/**
* @file        main.c
* @date        05/07/2021
* @author      Paul L. (@am0nsec)
* @version     1.0
* @brief
* @details
* @link
* @copyright   This project has been released under the GNU Public License v3 license.
*/
#include <windows.h>
#include <stdio.h>

#include "util.h"
#include "vssutil.h"

INT main() {

	// 1. Ensure that the process token as the SeBackupPrivilege privilege.
	EXIT_ON_FAILURE(AssertPrivilege());

	// 2. Initialise COM context
	EXIT_ON_FAILURE(InitialiseProcess());

	// 3. Get the interface
	IVssCoordinator* pIVssCoordinator = NULL;
	THROW_ON_FAILURE(CoCreateInstance(
		&CLSID_CVssCoordinator,
		NULL,
		(/*CLSCTX_REMOTE_SERVER |*/ CLSCTX_LOCAL_SERVER),
		&IID_IVssCoordinator,
		(LPVOID*)&pIVssCoordinator
	));
	THROW_ON_FAILURE(pIVssCoordinator->lpVtbl->SetContext(pIVssCoordinator, -1));

	// 4. Get the IVssEnumObject interface
	VSS_OBJECT_PROP* pVssSnapshots = NULL;
	LONG lNumberOfSnapshots = 0x00;

	VssUtilListSnapshots(pIVssCoordinator, &pVssSnapshots, &lNumberOfSnapshots);
	VssUtilDeleteSnapshots(pIVssCoordinator, pVssSnapshots, lNumberOfSnapshots);

	// xx. Uninitialise COM context and exit.
	THROW_ON_FAILURE(pIVssCoordinator->lpVtbl->Release(pIVssCoordinator));
	CoUninitialize();
	return EXIT_SUCCESS;
}