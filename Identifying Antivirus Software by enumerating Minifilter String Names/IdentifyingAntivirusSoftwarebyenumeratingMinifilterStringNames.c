#include <Windows.h>
#include <fltUser.h>
#include <stdio.h>

#pragma comment( lib, "fltlib" )

DWORD Win32FromHResult(HRESULT Result)
{
	if ((Result & 0xFFFF0000) == MAKE_HRESULT(SEVERITY_ERROR, FACILITY_WIN32, 0))
		return HRESULT_CODE(Result);

	if (Result == S_OK)
		return ERROR_SUCCESS;

	return ERROR_CAN_NOT_COMPLETE;
}
int main(VOID)
{
	DWORD dwError = ERROR_SUCCESS, dwBufferSize = 0;
	HRESULT Result;
	HANDLE Filter = INVALID_HANDLE_VALUE, ProcessHeap = GetProcessHeap();
	PFILTER_FULL_INFORMATION FilterInformation = NULL;

	FilterInformation = (PFILTER_FULL_INFORMATION)HeapAlloc(ProcessHeap, HEAP_ZERO_MEMORY, MAX_PATH);
	if (FilterInformation == NULL)
		goto FAILURE;

	Result = FilterFindFirst(FilterFullInformation, FilterInformation, MAX_PATH, &dwBufferSize, &Filter);
	if (Result != S_OK || Filter == INVALID_HANDLE_VALUE)
	{
		SetLastError(Win32FromHResult(Result));
		goto FAILURE;
	}

	_putws(FilterInformation->FilterNameBuffer);
	
	for (;;)
	{
		ZeroMemory(FilterInformation, dwBufferSize);
		Result = FilterFindNext(Filter, FilterFullInformation, FilterInformation, MAX_PATH, &dwBufferSize);
		if (Result != S_OK || Filter == INVALID_HANDLE_VALUE)
		{
			if (Win32FromHResult(Result) == ERROR_NO_MORE_ITEMS)
				break;

			SetLastError(Win32FromHResult(Result));
			goto FAILURE;
		}

		_putws(FilterInformation->FilterNameBuffer);
	}


	if (Filter)
		FilterFindClose(Filter);

	if (FilterInformation)
		HeapFree(ProcessHeap, HEAP_ZERO_MEMORY, FilterInformation);

	return ERROR_SUCCESS;

FAILURE:

	dwError = GetLastError();

	if (Filter)
		FilterFindClose(Filter);

	if (FilterInformation)
		HeapFree(ProcessHeap, HEAP_ZERO_MEMORY, FilterInformation);

	return dwError;
}