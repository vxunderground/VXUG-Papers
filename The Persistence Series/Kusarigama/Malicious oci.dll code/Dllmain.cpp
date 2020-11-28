// this code donated to us by Jonas Lyk (https://twitter.com/jonasLyk) 
#include <filesystem>   
#include <wtsapi32.h>

#include <Lmcons.h>
#include <iostream>
#include <string>
#include <Windows.h>

#include <wtsapi32.h>


#pragma comment(lib, "Wtsapi32.lib")

using namespace std;

#include <shellapi.h>

auto getUsername() {
    wchar_t usernamebuf[UNLEN + 1];
    DWORD size = UNLEN + 1;
    GetUserName((TCHAR*)usernamebuf, &size);
    static auto username = wstring{ usernamebuf };
    return username;
}

auto getProcessFilename() {
    wchar_t process_filenamebuf[MAX_PATH]{ 0x0000 };
    GetModuleFileName(0, process_filenamebuf, MAX_PATH);
    static auto process_filename = wstring{ process_filenamebuf };
    return process_filename;
}

auto getModuleFilename(HMODULE hModule = nullptr) {
    wchar_t module_filenamebuf[MAX_PATH]{ 0x0000 };
    if (hModule != nullptr) GetModuleFileName(hModule, module_filenamebuf, MAX_PATH);
    static auto module_filename = wstring{ module_filenamebuf };
    return module_filename;
}

bool showMessage() {
    Beep(4000, 400);
    Beep(4000, 400);
    Beep(4000, 400);

    auto m = L"This file:\n"s + getModuleFilename() + L"\nwas loaded by:\n"s + getProcessFilename() + L"\nrunning as:\n" + getUsername();
    auto message = (wchar_t*)m.c_str();
    DWORD messageAnswer{};
    WTSSendMessage(WTS_CURRENT_SERVER_HANDLE, WTSGetActiveConsoleSessionId(), (wchar_t*)L"", 0, message, lstrlenW(message) * 2, 0, 0, &messageAnswer, true);

    return true;
}
//static const auto init = spawnShell();

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    getModuleFilename(hModule);
    static auto const msgshown = showMessage();

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

