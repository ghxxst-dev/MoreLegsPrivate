#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")

#define OP_SUCCESS(status)  (((NTSTATUS)(status)) >= 0)
#define KEY_LEN     32
#define VECTOR_LEN  16

typedef struct _DATA_TRANSFORM {
    PBYTE   OutputData;
    DWORD   OutputSize;

    PBYTE   InputData;
    DWORD   InputSize;

    PBYTE   TransformKey;
    PBYTE   TransformVector;
} DATA_TRANSFORM, * PDATA_TRANSFORM;

BOOL TransformData(PDATA_TRANSFORM pDataOp) {
    BOOL                bSuccess = TRUE;
    BCRYPT_ALG_HANDLE   hProvider = NULL;
    BCRYPT_KEY_HANDLE   hKey = NULL;
    NTSTATUS            Status = 0;

    ULONG       cbResult = 0;
    DWORD       dwBlockLen = 0;
    DWORD       cbObjectLen = 0;
    PBYTE       pbObjectBuf = NULL;
    PBYTE       pbOutputBuf = NULL;
    DWORD       cbOutputLen = 0;

    Status = BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!OP_SUCCESS(Status)) {
        bSuccess = FALSE; goto Cleanup;
    }

    Status = BCryptGetProperty(hProvider, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbObjectLen, sizeof(DWORD), &cbResult, 0);
    if (!OP_SUCCESS(Status)) {
        bSuccess = FALSE; goto Cleanup;
    }

    Status = BCryptGetProperty(hProvider, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockLen, sizeof(DWORD), &cbResult, 0);
    if (!OP_SUCCESS(Status) || dwBlockLen != 16) {
        bSuccess = FALSE; goto Cleanup;
    }

    pbObjectBuf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbObjectLen);
    if (pbObjectBuf == NULL) {
        bSuccess = FALSE; goto Cleanup;
    }

    Status = BCryptSetProperty(hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!OP_SUCCESS(Status)) {
        bSuccess = FALSE; goto Cleanup;
    }

    Status = BCryptGenerateSymmetricKey(hProvider, &hKey, pbObjectBuf, cbObjectLen,
        (PBYTE)pDataOp->TransformKey, KEY_LEN, 0);
    if (!OP_SUCCESS(Status)) {
        bSuccess = FALSE; goto Cleanup;
    }

    Status = BCryptDecrypt(hKey, (PUCHAR)pDataOp->InputData, (ULONG)pDataOp->InputSize,
        NULL, pDataOp->TransformVector, VECTOR_LEN,
        NULL, 0, &cbOutputLen, BCRYPT_BLOCK_PADDING);
    if (!OP_SUCCESS(Status)) {
        bSuccess = FALSE; goto Cleanup;
    }

    pbOutputBuf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbOutputLen);
    if (pbOutputBuf == NULL) {
        bSuccess = FALSE; goto Cleanup;
    }

    Status = BCryptDecrypt(hKey, (PUCHAR)pDataOp->InputData, (ULONG)pDataOp->InputSize,
        NULL, pDataOp->TransformVector, VECTOR_LEN,
        pbOutputBuf, cbOutputLen, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!OP_SUCCESS(Status)) {
        bSuccess = FALSE; goto Cleanup;
    }

Cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hProvider) BCryptCloseAlgorithmProvider(hProvider, 0);
    if (pbObjectBuf) HeapFree(GetProcessHeap(), 0, pbObjectBuf);

    if (pbOutputBuf != NULL && bSuccess) {
        pDataOp->OutputData = pbOutputBuf;
        pDataOp->OutputSize = cbOutputLen;
    }

    return bSuccess;
}

BOOL ProcessBuffer(IN PVOID pInputBuffer, IN DWORD sInputSize,
    IN PBYTE pKey, IN PBYTE pVector,
    OUT PVOID* pOutputBuffer, OUT DWORD* sOutputSize) {
    if (!pInputBuffer || !sInputSize || !pKey || !pVector)
        return FALSE;

    DATA_TRANSFORM op = {
        .TransformKey = pKey,
        .TransformVector = pVector,
        .InputData = pInputBuffer,
        .InputSize = sInputSize
    };

    if (!TransformData(&op)) {
        return FALSE;
    }

    *pOutputBuffer = op.OutputData;
    *sOutputSize = op.OutputSize;

    return TRUE;
}
