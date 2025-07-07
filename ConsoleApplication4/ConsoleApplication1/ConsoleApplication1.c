#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ncrypt.h>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")


#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)













int main() {
    printf("started \n");

    NTSTATUS status = 0;

    NCRYPT_KEY_HANDLE hkey = 0;

    NCRYPT_KEY_HANDLE       hVerKey = 0;

    NCRYPT_PROV_HANDLE       hProv = 0;

    BCRYPT_ALG_HANDLE       hHashAlg = 0;

    BCRYPT_ALG_HANDLE hSignAlg = 0;

    BCRYPT_HASH_HANDLE      hHash = 0;

    DWORD                   cbDigest = 0;

    DWORD                   cbResult = 0;

    PBYTE                   pbHash = NULL;

    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbDigest);

    PBYTE cbSignature = NULL;

    DWORD cbBlob = 0;

    PBYTE pbBlob = NULL;

    const wchar_t pszCurveName[] = BCRYPT_ECC_CURVE_SECP256R1;

    const wchar_t pszAlgName[] = BCRYPT_ECDSA_P256_ALGORITHM;

    const wchar_t           keyName[] = L"A real key";

    const wchar_t* pszAlgNameList[] =
    {
        BCRYPT_ECC_CURVE_SECP256R1 ,
        BCRYPT_ECC_CURVE_SECP256K1,
        BCRYPT_ECC_CURVE_SECP384R1,
        BCRYPT_ECC_CURVE_SECP521R1,
        BCRYPT_ECC_CURVE_BRAINPOOLP160R1,
        BCRYPT_ECC_CURVE_25519
    };

    status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error1 0x%x \n", status);
        goto cleanup;
    }

    status = BCryptGetProperty(hHashAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbDigest, sizeof(cbDigest), &cbResult, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error2 0x%x \n", status);
        goto cleanup;
    }

    status = BCryptCreateHash(hHashAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error3 0x%x \n", status);
        goto cleanup;
    }

    static const  BYTE rgbMsg[] =
    {
        0x04, 0x87, 0xec, 0x66, 0xa8, 0xbf, 0x17, 0xa6,
        0xe3, 0x62, 0x6f, 0x1a, 0x55, 0xe2, 0xaf, 0x5e,
        0xbc, 0x54, 0xa4, 0xdc, 0x68, 0x19, 0x3e, 0x94,
    };

    status = BCryptHashData(hHash, (PBYTE)rgbMsg, sizeof(rgbMsg), 0);
    if (!NT_SUCCESS(status)) {
        printf("Error4 0x%x \n", status);
        goto cleanup;
    }

    status = BCryptFinishHash(hHash, pbHash, cbDigest, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error5 0x%x \n", status);
        goto cleanup;
    }

    NCryptDeleteKey(hkey, 0);

    status = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error1 0x%x \n", status);
        goto cleanup;
    }

    status = NCryptCreatePersistedKey(hProv, &hkey, BCRYPT_ECDSA_ALGORITHM, keyName, AT_SIGNATURE, NCRYPT_OVERWRITE_KEY_FLAG);
    if (!NT_SUCCESS(status)) {
        printf("Error2 0x%x \n", status);
        goto cleanup;
    }

    status = NCryptSetProperty(hkey, BCRYPT_ECC_CURVE_NAME, BCRYPT_ECC_CURVE_SECP256R1, (wcslen(BCRYPT_ECC_CURVE_SECP256R1) + 1) * sizeof(wchar_t), 0);
    if (!NT_SUCCESS(status)) {
        printf("Error2 set property 0x%x \n", status);
        goto cleanup;
    }
    status = NCryptFinalizeKey(hkey, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error3 0x%x \n", status);
        goto cleanup;
    }


    status = NCryptSignHash(hkey, NULL, pbHash, cbDigest, NULL, 0, &cbSignature, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error7 0x%x \n", status);
        goto cleanup;
    }

    PBYTE pbSignature = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbSignature);
    status = NCryptSignHash(hkey, NULL, pbHash, cbDigest, pbSignature, cbSignature, &cbSignature, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error7 0x%x \n", status);
        goto cleanup;
    }
    printf("signed \n");

    status = NCryptExportKey(hkey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, &cbBlob, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error exporting key 0x%x \n", status);
        goto cleanup;
    }
    pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
    status = NCryptExportKey(hkey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, pbBlob, cbBlob, &cbBlob, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error exporting2 key 0x%x", status);
        goto cleanup;
    }
    status = BCryptOpenAlgorithmProvider(
        &hSignAlg,
        BCRYPT_ECDSA_P256_ALGORITHM,
        NULL,
        0);
    if (!NT_SUCCESS(status)) {
        printf("Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto cleanup;
    }
    status = BCryptImportKeyPair(hSignAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hVerKey, pbBlob, cbBlob, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error importing key 0x%x", status);
        goto cleanup;
    }

    status = BCryptVerifySignature(hVerKey, NULL, pbHash, cbDigest, pbSignature, cbSignature, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error verifying 0x%x", status);
        goto cleanup;
    }

    printf("Verified \n");
cleanup:
    if (hkey != NULL) {
        NCryptDeleteKey(hkey, 0);
    }
    if (hkey != NULL) {
        NCryptDeleteKey(hVerKey, 0);
    }
    if (hSignAlg != NULL) {
        BCryptCloseAlgorithmProvider(hSignAlg, 0);
    }

    if (hHashAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hHashAlg, 0);
    }

    if (hHash != NULL)
    {
        BCryptDestroyHash(hHash);
    }

    if (pbHash != NULL)
    {
        HeapFree(GetProcessHeap(), 0, pbHash);
    }

    if (hProv != NULL) {
        NCryptFreeObject(hProv);
    }

    return 1;
}

