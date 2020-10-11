#include <Windows.h>
#include <powersetting.h>
#include <powrprof.h>

#define WIN32_LEAN_AND_MEAN

typedef DWORD(WINAPI* POWERSETTINGREGISTERNOTIFICATION)(LPCGUID, DWORD, HANDLE, PHPOWERNOTIFY);
typedef DWORD(WINAPI* POWERSETTINGUNREGISTERNOTIFICATION)(HPOWERNOTIFY);

ULONG CALLBACK HandlePowerNotifications(PVOID Context, ULONG Type, PVOID Setting);

int main(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	HMODULE hLibrary;
	POWERSETTINGREGISTERNOTIFICATION _PowerSettingRegisterNotification = NULL;
	POWERSETTINGUNREGISTERNOTIFICATION _PowerSettingUnregisterNotification = NULL;
	DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS NotificationsParameters;
	HANDLE hNotificationRegister = NULL;

	hLibrary = LoadLibrary(L"powrprof.dll");
	if (hLibrary == NULL)
		goto FAILURE;

	_PowerSettingRegisterNotification = (POWERSETTINGREGISTERNOTIFICATION)GetProcAddress(hLibrary, "PowerSettingRegisterNotification");
	_PowerSettingUnregisterNotification = (POWERSETTINGUNREGISTERNOTIFICATION)GetProcAddress(hLibrary, "PowerSettingUnregisterNotification");
	
	if (!_PowerSettingRegisterNotification || !_PowerSettingUnregisterNotification)
		goto FAILURE;

	NotificationsParameters.Callback = HandlePowerNotifications;
	NotificationsParameters.Context = NULL;

	if (_PowerSettingRegisterNotification(&GUID_CONSOLE_DISPLAY_STATE, DEVICE_NOTIFY_CALLBACK,
		(HANDLE)&NotificationsParameters, &hNotificationRegister) != ERROR_SUCCESS)
	{
		goto FAILURE;
	}

	if (SetThreadExecutionState(ES_AWAYMODE_REQUIRED | ES_CONTINUOUS | ES_SYSTEM_REQUIRED) == NULL)
		goto FAILURE;

	while (1){ Sleep(100); }

	if (hNotificationRegister)
		_PowerSettingUnregisterNotification(hNotificationRegister);

	return ERROR_SUCCESS;

FAILURE:

	dwError = GetLastError();

	if (hNotificationRegister)
		_PowerSettingUnregisterNotification(hNotificationRegister);

	return dwError;

}

ULONG CALLBACK HandlePowerNotifications(PVOID Context, ULONG Type, PVOID Setting)
{
	PPOWERBROADCAST_SETTING PowerSettings = (PPOWERBROADCAST_SETTING)Setting;

	if (Type == PBT_POWERSETTINGCHANGE && PowerSettings->PowerSetting == GUID_CONSOLE_DISPLAY_STATE)
	{
		switch (*PowerSettings->Data)
		{
			case 0x0:
			case 0x2:
			{
				Sleep(10000);
				MessageBoxW(NULL, L"Spooky Payload", L"", MB_OK);
				break;
			}

			case 0x1:
			{
				Sleep(1);
				break;
			}

			default:
			{
				break;
			}
		}
	}

	return ERROR_SUCCESS;
}