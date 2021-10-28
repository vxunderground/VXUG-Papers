#include <Windows.h>
#pragma warning(disable:6011)


#define CUDACALL __stdcall
typedef struct PCUDE_CONTEXT* CUDA_CONTEXT;

typedef INT(CUDACALL* CUDAMEMORYALLOCATE)(ULONG_PTR, SIZE_T);
typedef INT(CUDACALL* CUDAINIT)(INT);
typedef INT(CUDACALL* CUDAGETDEVICECOUNT)(PINT);
typedef INT(CUDACALL* CUDAGETDEVICE)(PINT, INT);
typedef INT(CUDACALL* CUDACREATECONTEXT)(CUDA_CONTEXT*, DWORD, INT);
typedef INT(CUDACALL* CUDADESTROYCONTEXT)(CUDA_CONTEXT*);
typedef INT(CUDACALL* CUDAMEMORYCOPYTODEVICE)(ULONG_PTR, PVOID, SIZE_T);
typedef INT(CUDACALL* CUDAMEMORYCOPYTOHOST)(PVOID, ULONG_PTR, SIZE_T);
typedef INT(CUDACALL* CUDAMEMORYFREE)(ULONG_PTR);

#define CUDA_SUCCESS 0

typedef struct _NVIDIA_API_TABLE {
	HMODULE NvidiaLibary;
	CUDAMEMORYALLOCATE CudaMemoryAllocate;
	CUDAINIT CudaInit;
	CUDAGETDEVICECOUNT CudaGetDeviceCount;
	CUDAGETDEVICE CudaGetDevice;
	CUDACREATECONTEXT CudaCreateContext;
	CUDAMEMORYCOPYTODEVICE CudaMemoryCopyToDevice;
	CUDAMEMORYCOPYTOHOST CudaMemoryCopyToHost;
	CUDAMEMORYFREE CudaMemoryFree;
	CUDADESTROYCONTEXT CudaDestroyContext;
} NVIDIA_API_TABLE, *PNVIDIA_API_TABLE;

SIZE_T StringLengthW(LPCWSTR String)
{
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

PWCHAR StringLocateCharW(PWCHAR String, INT Character)
{
	do
	{
		if (*String == Character)
			return (PWCHAR)String;

	} while (*String++);

	return NULL;
}

INT StringCompareStringRegionW(PWCHAR String1, PWCHAR String2, SIZE_T Count)
{
	UCHAR Block1, Block2;
	while (Count-- > 0)
	{
		Block1 = (UCHAR)*String1++;
		Block2 = (UCHAR)*String2++;

		if (Block1 != Block2)
			return Block1 - Block2;

		if (Block1 == '\0')
			return 0;
	}

	return 0;
}

PWCHAR StringFindSubstringW(PWCHAR String1, PWCHAR String2)
{
	PWCHAR pPointer = String1;
	DWORD Length = (DWORD)StringLengthW(String2);

	for (; (pPointer = StringLocateCharW(pPointer, *String2)) != 0; pPointer++)
	{
		if (StringCompareStringRegionW(pPointer, String2, Length) == 0)
			return (PWCHAR)pPointer;
	}

	return NULL;
}

PWCHAR StringCopyW(PWCHAR String1, PWCHAR String2)
{
	PWCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

PWCHAR StringConcatW(PWCHAR String, PWCHAR String2)
{
	StringCopyW(&String[StringLengthW(String)], String2);

	return String;
}

BOOL IsNvidiaGraphicsCardPresent(VOID)
{
    DISPLAY_DEVICEW DisplayDevice; RtlZeroMemory(&DisplayDevice, sizeof(DISPLAY_DEVICEW));
    DisplayDevice.cb = sizeof(DISPLAY_DEVICEW);

	DWORD dwDeviceId = ERROR_SUCCESS;

	while (EnumDisplayDevicesW(NULL, dwDeviceId, &DisplayDevice, 0))
	{
		if (StringFindSubstringW(DisplayDevice.DeviceString, (PWCHAR)L"NVIDIA") != NULL)
			return TRUE;
	}

	return FALSE;
}

BOOL InitNvidiaCudaAPITable(PNVIDIA_API_TABLE Api)
{
	Api->NvidiaLibary = LoadLibraryW(L"nvcuda.dll");
	if (Api->NvidiaLibary == NULL)
		return FALSE;

	Api->CudaCreateContext = (CUDACREATECONTEXT)GetProcAddress(Api->NvidiaLibary, "cuCtxCreate_v2");
	Api->CudaGetDevice = (CUDAGETDEVICE)GetProcAddress(Api->NvidiaLibary, "cuDeviceGet");
	Api->CudaGetDeviceCount = (CUDAGETDEVICECOUNT)GetProcAddress(Api->NvidiaLibary, "cuDeviceGetCount");
	Api->CudaInit = (CUDAINIT)GetProcAddress(Api->NvidiaLibary, "cuInit");
	Api->CudaMemoryAllocate = (CUDAMEMORYALLOCATE)GetProcAddress(Api->NvidiaLibary, "cuMemAlloc_v2");
	Api->CudaMemoryCopyToDevice = (CUDAMEMORYCOPYTODEVICE)GetProcAddress(Api->NvidiaLibary, "cuMemcpyHtoD_v2");
	Api->CudaMemoryCopyToHost = (CUDAMEMORYCOPYTOHOST)GetProcAddress(Api->NvidiaLibary, "cuMemcpyDtoH_v2");
	Api->CudaMemoryFree = (CUDAMEMORYFREE)GetProcAddress(Api->NvidiaLibary, "cuMemFree_v2");
	Api->CudaDestroyContext = (CUDADESTROYCONTEXT)GetProcAddress(Api->NvidiaLibary, "cuCtxDestroy");

	if (!Api->CudaCreateContext || !Api->CudaGetDevice || !Api->CudaGetDeviceCount || !Api->CudaInit || !Api->CudaDestroyContext)
		return FALSE;

	if (!Api->CudaMemoryAllocate || !Api->CudaMemoryCopyToDevice || !Api->CudaMemoryCopyToHost || !Api->CudaMemoryFree)
		return FALSE;

	return TRUE;
}

ULONG_PTR RtlAllocateGpuMemory(PNVIDIA_API_TABLE Api, DWORD ByteSize)
{
	ULONG_PTR GpuBufferPointer = NULL;

	if (ByteSize == 0)
		return NULL;

	if (Api->CudaMemoryAllocate((ULONG_PTR )&GpuBufferPointer, ByteSize) != CUDA_SUCCESS)
		return NULL;

	return GpuBufferPointer;

}

INT main(VOID)
{
	/********************************************************************
	*					Variables
	********************************************************************/

	//Application variables
	DWORD dwError = ERROR_SUCCESS;
	BOOL bFlag = FALSE;

	//NVIDIA related variables
	NVIDIA_API_TABLE Api = { 0 };
	INT DeviceCount = 0;
	INT Device = 0;
	CUDA_CONTEXT Context = NULL;;
	ULONG_PTR GpuMemory = NULL;

	//Subroutine related variables, unimportant to proof-of-concept
	WCHAR BinaryPath[MAX_PATH * sizeof(WCHAR)] = { 0 };
	HANDLE hHandle = INVALID_HANDLE_VALUE;
	PBYTE DataBuffer = NULL;
	HANDLE ProcessHeap = GetProcessHeap();
	DWORD dwRead = 0;

	/********************************************************************
	*					Start
	*********************************************************************
	* 
	*	IsNvidiaGraphicsCardPresent() invokes the EnumDisplayDevicesW and
	*	performs a string comparison on DISPLAY_DEVICEW member
	*	DeviceString to look for the presence of NVIDIA. If NVIDIA string
	*	is present IsNvidiaGraphicsCardPresent() returns true else false.
	*	If IsNvidiaGraphicsCardPresent() returns false the application
	*	terminates. This proof-of-concept is NVIDIA specific.
	* 
	*	If IsNvidiaGraphicsCardPresent() returns true, we make a
	*	subsequent function call to InitNvidiaCudaAPITable(). 
	*	InitNvidiaCudaAPITable() populates a NVIDIA_API_TABLE structure
	*	whose members are function pointers to NVIDIA-related APIs omit
	*	the NvidiaLibrary HMODULE member whose value is returned from a
	*	call to LoadLibrary.
	*
	*	Anyway, enjoy the proof-of-concept.
	*	With love, smelly__vx
	*	vx-underground.org
	*	
	********************************************************************/

	if (!IsNvidiaGraphicsCardPresent())
		goto EXIT_ROUTINE;

	if (!InitNvidiaCudaAPITable(&Api))
		goto EXIT_ROUTINE;

	/********************************************************************
	*					Unimportant section
	*********************************************************************
	*
	*	This section performs trivial tasks unrelated to the core
	*	concept being illustrated in this proof of concept. The code
	*	below assembles a path to the desktop by using
	*	GetEnvironmentVariableW and appending a hardcoded path. The hard
	*	coded path is a binary present on the desktop (must be created
	*	by the user).
	* 
	*	Once creating the desktop path in memory, we invoke CreateFile
	*	and get a handle to file on the desktop. Subsequently this code
	*	gets the file size, allocates it in memory, and reads the content
	*	into member (type PBYTE).
	* 
	********************************************************************/

	if (GetEnvironmentVariableW(L"USERPROFILE", BinaryPath, (MAX_PATH * sizeof(WCHAR))) == 0)
		goto EXIT_ROUTINE;

	if (StringConcatW(BinaryPath, (PWCHAR)L"\\Desktop\\Demo.txt") == NULL)
		goto EXIT_ROUTINE;

	hHandle = CreateFileW(BinaryPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hHandle == INVALID_HANDLE_VALUE)
		goto EXIT_ROUTINE;

	dwError = GetFileSize(hHandle, NULL);
	if (dwError == INVALID_FILE_SIZE)
		goto EXIT_ROUTINE;

	DataBuffer = (PBYTE)HeapAlloc(ProcessHeap, HEAP_ZERO_MEMORY, dwError);
	if (DataBuffer == NULL)
		goto EXIT_ROUTINE;

	if (!ReadFile(hHandle, DataBuffer, dwError, &dwRead, NULL))
		goto EXIT_ROUTINE;

	dwError = ERROR_SUCCESS;

	/********************************************************************
	*					Unimportant code segment end
	********************************************************************/

	/********************************************************************
	*					NVIDIA CUDA Code segment
	*********************************************************************
	* 
	*	The code below copies content from the data file read off the
	*	desktop onto the GPU, frees the heap, then copies the data back
	* 
	*	CUDA_SUCCESS is defined as 0 (zero). Successful CUDA invocations
	*	return 0 (zero).
	* 
	*	CudaInit(0) is required to initialize NVIDIA API interface. The
	*	subsequent function calls, CudaGetDeviceCount, and 
	*	CudaGetDevice are generic NVIDIA functions to enumerating and
	*	identifying GPU devices - in the unlikely event more than one
	*	GPU is present.
	* 
	*	The handle returned by CudaGetDevice is used to create a CUDA
	*	context - the state of the application, how two consecutive 
	*	API calls are related to each other while utilizing the CUDA
	*	runtime API.
	* 
	*	This code forwards to the NVIDIA driver.
	* 
	*	After a context is successfully created - we allocate memory
	*	on the GPU via our wrapper function, RtlAllocateGpuMemory, which
	*	returns a ULONG_PTR, a pointer to the allocated GPU memory.
	*	The calls that proceed this first copy data to the GPU, and
	*	finally, retrive the data back. This is illustrated by this
	*	proof-of-concept freeing the heap which contained data which was
	*	previously stored in the DataBuffer variable. 
	* 
	********************************************************************/

	if (Api.CudaInit(0) != CUDA_SUCCESS)
		goto EXIT_ROUTINE;

	if (Api.CudaGetDeviceCount(&DeviceCount) != CUDA_SUCCESS || DeviceCount == 0)
		goto EXIT_ROUTINE;

	if (Api.CudaGetDevice(&Device, DeviceCount - 1) != CUDA_SUCCESS)
		goto EXIT_ROUTINE;

	if (Api.CudaCreateContext(&Context, 0, Device) != CUDA_SUCCESS)
		goto EXIT_ROUTINE;

	GpuMemory = RtlAllocateGpuMemory(&Api, dwRead);
	if (GpuMemory == NULL)
		goto EXIT_ROUTINE;

	if (Api.CudaMemoryCopyToDevice(GpuMemory, DataBuffer, dwRead) != CUDA_SUCCESS)
		goto EXIT_ROUTINE;

	/********************************************************************
	*					Unimportant section
	*********************************************************************
	*
	*	Frees the heap, to illustrate the DataBuffer variable is indeed
	*	empty, containing no data. We then reallocate the buffer and
	*	copy the contents from the GPU back onto the hosts heap.
	* 
	********************************************************************/
	if (DataBuffer)
		HeapFree(ProcessHeap, HEAP_ZERO_MEMORY, DataBuffer);

	Sleep(1000);

	DataBuffer = (PBYTE)HeapAlloc(ProcessHeap, HEAP_ZERO_MEMORY, dwRead);
	if (DataBuffer == NULL)
		goto EXIT_ROUTINE;

	/********************************************************************
	*					Unimportant code segment end
	********************************************************************/

	if (Api.CudaMemoryCopyToHost(DataBuffer, GpuMemory, dwRead) != CUDA_SUCCESS)
		goto EXIT_ROUTINE;

	/********************************************************************
	*					EXIT_ROUTINE
	*********************************************************************
	* 
	*	bFlag is a generic variable. Its value by default, FALSE,
	*	indicates whether or not the application has entered the 
	*	exit routine normally. If the code has finished execution, then
	*	bFlag will be set to TRUE indicating there has been no issues.
	*	Otherwise, bFlag being FALSE indicates failure and GetLastError
	*	is invoked.
	* 
	*	Regardless of failure, each variable is checked to determine if
	*	it needs to be freed or unloaded.
	* 
	********************************************************************/

	bFlag = TRUE;

EXIT_ROUTINE:

	if (!bFlag)
		dwError = GetLastError();

	if (DataBuffer)
		HeapFree(ProcessHeap, HEAP_ZERO_MEMORY, DataBuffer);

	if (GpuMemory != NULL)
		Api.CudaMemoryFree(GpuMemory);

	if (Context != NULL)
		Api.CudaDestroyContext(&Context);

	if (Api.NvidiaLibary)
		FreeLibrary(Api.NvidiaLibary);

	if (hHandle)
		CloseHandle(hHandle);

	return dwError;
}