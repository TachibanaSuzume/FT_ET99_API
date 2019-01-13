#include "stdafx.h"
#include <string>

using namespace std;

#define ET_STATUS			unsigned long
#define ET_API				__stdcall
typedef void*				ET_HANDLE;

typedef ET_STATUS(WINAPI * api_et_FindToken)(unsigned char* pid, int * count);
typedef ET_STATUS(WINAPI * api_MD5_HMAC)(unsigned char * pucText, unsigned long   ulText_Len, unsigned char * pucKey, unsigned long   ulKey_Len, unsigned char * pucToenKey, unsigned char * pucDigest);
typedef ET_STATUS(WINAPI * api_et_ChangeUserPIN)(ET_HANDLE hHandle, unsigned char* pucOldPIN, unsigned char* pucNewPIN);
typedef ET_STATUS(WINAPI * api_et_CloseToken)(ET_HANDLE hHandle);
typedef ET_STATUS(WINAPI * api_et_GenPID)(ET_HANDLE hHandle, int SeedLen, unsigned char* pucSeed, unsigned char* pid);
typedef ET_STATUS(WINAPI * api_et_GenRandom)(ET_HANDLE hHandle, unsigned char* pucRandBuf);
typedef ET_STATUS(WINAPI * api_et_GenSOPIN)(ET_HANDLE hHandle, int SeedLen, unsigned char* pucSeed, unsigned char* pucNewSoPIN);
typedef ET_STATUS(WINAPI * api_et_GetSN)(ET_HANDLE hHandle, unsigned char* pucSN);
typedef ET_STATUS(WINAPI * api_et_HMAC_MD5)(ET_HANDLE hHandle, int keyID, int textLen, unsigned char* pucText, unsigned char *digest);
typedef ET_STATUS(WINAPI * api_et_OpenToken)(ET_HANDLE* hHandle, unsigned char* pid, int index);
typedef ET_STATUS(WINAPI * api_et_Read)(ET_HANDLE hHandle, WORD offset, int Len, unsigned char* pucReadBuf);
typedef ET_STATUS(WINAPI * api_et_ResetPIN)(ET_HANDLE hHandle, unsigned char* pucSoPIN);
typedef ET_STATUS(WINAPI * api_et_ResetSecurityState)(ET_HANDLE hHandle);
typedef ET_STATUS(WINAPI * api_et_SetKey)(ET_HANDLE hHandle, int Keyid, unsigned char* pucKeyBuf);
typedef ET_STATUS(WINAPI * api_et_SetupToken)(ET_HANDLE hHandle, BYTE bSoPINRetries, BYTE bUserPINRetries, BYTE bUserReadOnly, BYTE bBack);
typedef ET_STATUS(WINAPI * api_et_TurnOffLED)(ET_HANDLE hHandle);
typedef ET_STATUS(WINAPI * api_et_TurnOnLED)(ET_HANDLE hHandle);
typedef ET_STATUS(WINAPI * api_et_Verify)(ET_HANDLE hHandle, int Flags, unsigned char* pucPIN);
typedef ET_STATUS(WINAPI * api_et_Write)(ET_HANDLE hHandle, WORD offset, int Len, unsigned char* pucWriteBuf);

api_et_FindToken e_api_et_FindToken = NULL;
api_MD5_HMAC e_api_MD5_HMAC = NULL;
api_et_ChangeUserPIN e_api_et_ChangeUserPIN = NULL;
api_et_CloseToken e_api_et_CloseToken = NULL;
api_et_GenPID e_api_et_GenPID = NULL;
api_et_GenRandom e_api_et_GenRandom = NULL;
api_et_GenSOPIN e_api_et_GenSOPIN = NULL;
api_et_GetSN e_api_et_GetSN = NULL;
api_et_HMAC_MD5 e_api_et_HMAC_MD5 = NULL;
api_et_OpenToken e_api_et_OpenToken = NULL;
api_et_Read e_api_et_Read = NULL;
api_et_ResetPIN e_api_et_ResetPIN = NULL;
api_et_ResetSecurityState e_api_et_ResetSecurityState = NULL;
api_et_SetKey e_api_et_SetKey = NULL;
api_et_SetupToken e_api_et_SetupToken = NULL;
api_et_TurnOffLED e_api_et_TurnOffLED = NULL;
api_et_TurnOnLED e_api_et_TurnOnLED = NULL;
api_et_Verify e_api_et_Verify = NULL;
api_et_Write e_api_et_Write = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	hModule = LoadLibraryW(L"ET99.dll");
	if (hModule != NULL)
	{
		e_api_et_FindToken = (api_et_FindToken)GetProcAddress(hModule, "et_FindToken");
		e_api_MD5_HMAC = (api_MD5_HMAC)GetProcAddress(hModule, "MD5_HMAC");
		e_api_et_ChangeUserPIN = (api_et_ChangeUserPIN)GetProcAddress(hModule, "et_ChangeUserPIN");
		e_api_et_CloseToken = (api_et_CloseToken)GetProcAddress(hModule, "et_CloseToken");
		e_api_et_GenPID = (api_et_GenPID)GetProcAddress(hModule, "et_GenPID");
		e_api_et_GenRandom = (api_et_GenRandom)GetProcAddress(hModule, "et_GenRandom");
		e_api_et_GenSOPIN = (api_et_GenSOPIN)GetProcAddress(hModule, "et_GenSOPIN");
		e_api_et_GetSN = (api_et_GetSN)GetProcAddress(hModule, "et_GetSN");
		e_api_et_HMAC_MD5 = (api_et_HMAC_MD5)GetProcAddress(hModule, "et_HMAC_MD5");
		e_api_et_OpenToken = (api_et_OpenToken)GetProcAddress(hModule, "et_OpenToken");
		e_api_et_Read = (api_et_Read)GetProcAddress(hModule, "et_Read");
		e_api_et_ResetPIN = (api_et_ResetPIN)GetProcAddress(hModule, "et_ResetPIN");
		e_api_et_ResetSecurityState = (api_et_ResetSecurityState)GetProcAddress(hModule, "et_ResetSecurityState");
		e_api_et_SetKey = (api_et_SetKey)GetProcAddress(hModule, "et_SetKey");
		e_api_et_SetupToken = (api_et_SetupToken)GetProcAddress(hModule, "et_SetupToken");
		e_api_et_TurnOffLED = (api_et_TurnOffLED)GetProcAddress(hModule, "et_TurnOffLED");
		e_api_et_TurnOnLED = (api_et_TurnOnLED)GetProcAddress(hModule, "et_TurnOnLED");
		e_api_et_Verify = (api_et_Verify)GetProcAddress(hModule, "et_Verify");
		e_api_et_Write = (api_et_Write)GetProcAddress(hModule, "et_Write");
		FreeLibrary(hModule);
	}
	else {
		return false;
	}
	return TRUE;
}

ET_STATUS ET_API et_FindToken(unsigned char* pid, int * count)
{
	if ((string)(char*)pid == (string)"FFFFFFFF") {
		return e_api_et_FindToken((unsigned char *)"FFDE1EE1", count);
	}
	return e_api_et_FindToken(pid, count);
}

ET_STATUS ET_API MD5_HMAC(unsigned char * pucText, unsigned long   ulText_Len, unsigned char * pucKey, unsigned long   ulKey_Len, unsigned char * pucToenKey, unsigned char * pucDigest)
{
	return e_api_MD5_HMAC(pucText, ulText_Len, pucKey, ulKey_Len, pucToenKey, pucDigest);
}

ET_STATUS ET_API et_ChangeUserPIN(ET_HANDLE hHandle, unsigned char* pucOldPIN, unsigned char* pucNewPIN)
{
	return e_api_et_ChangeUserPIN(hHandle, pucOldPIN, pucNewPIN);
}

ET_STATUS ET_API et_CloseToken(ET_HANDLE hHandle)
{
	return e_api_et_CloseToken(hHandle);
}

ET_STATUS ET_API et_GenPID(ET_HANDLE hHandle, int SeedLen, unsigned char* pucSeed, unsigned char* pid)
{
	return e_api_et_GenPID(hHandle, SeedLen, pucSeed, pid);
}

ET_STATUS ET_API et_GenRandom(ET_HANDLE hHandle, unsigned char* pucRandBuf)
{
	return e_api_et_GenRandom(hHandle, pucRandBuf);
}

ET_STATUS ET_API et_GenSOPIN(ET_HANDLE hHandle, int SeedLen, unsigned char* pucSeed, unsigned char* pucNewSoPIN)
{
	return e_api_et_GenSOPIN(hHandle, SeedLen, pucSeed, pucNewSoPIN);
}

ET_STATUS ET_API et_GetSN(ET_HANDLE hHandle, unsigned char* pucSN)
{
	return e_api_et_GetSN(hHandle, pucSN);
}

ET_STATUS ET_API et_HMAC_MD5(ET_HANDLE hHandle, int keyID, int textLen, unsigned char* pucText, unsigned char *digest)
{
	return e_api_et_HMAC_MD5(hHandle, keyID, textLen, pucText, digest);
}

ET_STATUS ET_API et_OpenToken(ET_HANDLE* hHandle, unsigned char* pid, int index)
{
	if ((string)(char*)pid == (string)"FFFFFFFF") {
		return e_api_et_OpenToken(hHandle, (unsigned char *)"FFDE1EE1", index);
	}
	return e_api_et_OpenToken(hHandle, pid, index);
}

ET_STATUS ET_API et_Read(ET_HANDLE hHandle, WORD offset, int Len, unsigned char* pucReadBuf)
{
	return e_api_et_Read(hHandle, offset, Len, pucReadBuf);
}

ET_STATUS ET_API et_ResetPIN(ET_HANDLE hHandle, unsigned char* pucSoPIN)
{
	return e_api_et_ResetPIN(hHandle, pucSoPIN);
}

ET_STATUS ET_API et_ResetSecurityState(ET_HANDLE hHandle)
{
	return e_api_et_ResetSecurityState(hHandle);
}

ET_STATUS ET_API et_SetKey(ET_HANDLE hHandle, int Keyid, unsigned char* pucKeyBuf)
{
	return e_api_et_SetKey(hHandle, Keyid, pucKeyBuf);
}

ET_STATUS ET_API et_SetupToken(ET_HANDLE hHandle, BYTE bSoPINRetries, BYTE bUserPINRetries, BYTE bUserReadOnly, BYTE bBack)
{
	return e_api_et_SetupToken(hHandle, bSoPINRetries, bUserPINRetries, bUserReadOnly, bBack);
}

ET_STATUS ET_API et_TurnOffLED(ET_HANDLE hHandle)
{
	return e_api_et_TurnOffLED(hHandle);
}

ET_STATUS ET_API et_TurnOnLED(ET_HANDLE hHandle)
{
	return e_api_et_TurnOnLED(hHandle);
}

ET_STATUS ET_API et_Verify(ET_HANDLE hHandle, int Flags, unsigned char* pucPIN)
{
	return e_api_et_Verify(hHandle, Flags, pucPIN);
}

ET_STATUS ET_API et_Write(ET_HANDLE hHandle, WORD offset, int Len, unsigned char* pucWriteBuf)
{
	return e_api_et_Write(hHandle, offset, Len, pucWriteBuf);
}

extern "C" void MD5_HMAC();
extern "C" void et_ChangeUserPIN();
extern "C" void et_CloseToken();
extern "C" void et_FindToken();
extern "C" void et_GenPID();
extern "C" void et_GenRandom();
extern "C" void et_GenSOPIN();
extern "C" void et_GetSN();
extern "C" void et_HMAC_MD5();
extern "C" void et_OpenToken();
extern "C" void et_Read();
extern "C" void et_ResetPIN();
extern "C" void et_ResetSecurityState();
extern "C" void et_SetKey();
extern "C" void et_SetupToken();
extern "C" void et_TurnOffLED();
extern "C" void et_TurnOnLED();
extern "C" void et_Verify();
extern "C" void et_Write();