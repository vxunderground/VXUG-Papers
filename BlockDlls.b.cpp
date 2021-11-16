/*******************************************************************

	I recently re-read a paper from Adam Chester titled: 
	"Protecting Your Malware with blockdlls and ACG"
	link: https://blog.xpnsec.com/protecting-your-malware/

	It was neat, I was curious how the APIs in this code 
	worked, so I decided to reverse them. The tl;dr is
	that the functions used to block non-MS sign DLLs
	is very-very easy to implement without using or 
	importing the functions:

	InitializeProcThreadAttributeList
	UpdateProcThreadAttribute

	I was able to recreate these functions in just
	a few lines of C code and some IDA F5s.

	Thanks to DTM, Jonas Lyk, and coldzer0 to helping me
	trim the fat off these APIs. Under the hood these
	functions do lots of unnecessary things (for our purpose)
	and they helped speed up the process.

	Anyway, nothing revolutionary, but its neat. :)

	-smelly

*********************************************************************/


#include <Windows.h>

typedef struct _PROC_THREAD_ATTRIBUTE { 
	ULONG64 Attribute; 
	ULONG64 Size; 
	ULONG64 Value; 
}PROC_THREAD_ATTRIBUTE, *PPROC_THREAD_ATTRIBUTE;

typedef struct _PROC_THREAD_ATTRIBUTE_LIST {
	ULONG PresentFlags;
	ULONG AttributeCount;
	ULONG LastAttribute;
	ULONG SpareUlong0;
	struct _PROC_THREAD_ATTRIBUTE* ExtendedFlagsAttribute;
	struct _PROC_THREAD_ATTRIBUTE Attributes[1];
}PROC_THREAD_ATTRIBUTE_LIST, * PPROC_THREAD_ATTRIBUTE_LIST;

BOOL RtlInitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize)
{
	BOOL bFlag = FALSE;
	DWORD dwSize = ERROR_SUCCESS;

	if (dwFlags || (dwAttributeCount > 0x1B))
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return bFlag;
	}

	dwSize = (24 * (dwAttributeCount + 1));

	if (lpAttributeList && *lpSize >= dwSize)
	{
		lpAttributeList->PresentFlags = 0;
		lpAttributeList->ExtendedFlagsAttribute = 0;
		lpAttributeList->AttributeCount = dwAttributeCount;
		lpAttributeList->LastAttribute = 0;
		bFlag = TRUE;
	}
	else
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		
	*lpSize = dwSize;
	return bFlag;
}

SIZE_T RtlGetProcThreadAttributeListSize(VOID)
{
	SIZE_T dwSize = 0;

	RtlInitializeProcThreadAttributeList(NULL, 1, 0, &dwSize);

	return dwSize;
}

VOID RtlUpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST AttributeList, DWORD_PTR Attribute, PVOID Policy, SIZE_T Size)
{
	PPROC_THREAD_ATTRIBUTE ExtendedAttributes;

	AttributeList->PresentFlags |= (1 << (Attribute & 0x0000FFFF));

	ExtendedAttributes = AttributeList->Attributes;
	ExtendedAttributes->Attribute = Attribute;
	ExtendedAttributes->Size = Size;
	ExtendedAttributes->Value = (ULONG64)Policy;
	AttributeList->LastAttribute++;

	return;
}

INT main(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	BOOL bFlag = FALSE;
	
	PROCESS_INFORMATION Pi; ZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
	STARTUPINFOEXW Si; ZeroMemory(&Si, sizeof(STARTUPINFOEXW));
	Si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
	PPROC_THREAD_ATTRIBUTE_LIST ThreadAttributes = NULL;
	SIZE_T dwAttributeSize = 0;
	DWORD64 Policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	dwAttributeSize = RtlGetProcThreadAttributeListSize();
	if (dwAttributeSize == 0)
		goto EXIT_ROUTINE;

	ThreadAttributes = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwAttributeSize);
	if (ThreadAttributes == NULL)
		goto EXIT_ROUTINE;

	if (!RtlInitializeProcThreadAttributeList(ThreadAttributes, 1, 0, &dwAttributeSize))
		goto EXIT_ROUTINE;

	RtlUpdateProcThreadAttribute(ThreadAttributes, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &Policy, sizeof(DWORD64));

	Si.lpAttributeList = ThreadAttributes;

	if (!CreateProcessW((PWCHAR)L"C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &Si.StartupInfo, &Pi))
		goto EXIT_ROUTINE;

	WaitForSingleObject(Pi.hProcess, INFINITE);

	bFlag = TRUE;

EXIT_ROUTINE:

	if (!bFlag)
		dwError = GetLastError();

	if (ThreadAttributes)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, (PPROC_THREAD_ATTRIBUTE_LIST)ThreadAttributes);

	if(Pi.hProcess)
		CloseHandle(Pi.hProcess);

	if(Pi.hThread)
		CloseHandle(Pi.hThread);

	return dwError;
}