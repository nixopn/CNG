#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ncrypt.h>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")


#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)



void CrHash(NTSTATUS *status, BCRYPT_ALG_HANDLE *hHashAlg, BCRYPT_HASH_HANDLE *hHash, DWORD cbDigest, DWORD cbResult, PBYTE msg, PBYTE pbHash) {
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbDigest);
    status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error1 0x%x \n", status);
        goto cleanupCrHash;
    }
    status = BCryptGetProperty(hHashAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbDigest, sizeof(cbDigest), &cbResult, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error2 0x%x \n", status);
        goto cleanupCrHash;
    }
    status = BCryptCreateHash(hHashAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error3 0x%x \n", status);
        goto cleanupCrHash;
    }

    status = BCryptHashData(hHash, (PBYTE)msg, sizeof(msg), 0);
    if (!NT_SUCCESS(status)) {
        printf("Error4 0x%x \n", status);
        goto cleanupCrHash;
    }


    status = BCryptFinishHash(hHash, pbHash, cbDigest, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error5 0x%x \n", status);
        goto cleanupCrHash;
    }

cleanupCrHash:
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
}


int main() {
    printf("started \n");
    NTSTATUS status = 0;
    BCRYPT_KEY_HANDLE hkey = 0;
    BCRYPT_KEY_HANDLE       hVerKey = 0;
    BCRYPT_ALG_HANDLE       hAlg = 0;

    BCRYPT_ALG_HANDLE       hHashAlg = 0;
    BCRYPT_HASH_HANDLE      hHash = 0;


    DWORD                   cbDigest = 0;

    DWORD                   cbResult = 0;

    PBYTE                   pbHash = NULL;

    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbDigest);

    PBYTE cbSignature = NULL;

    DWORD cbBlob = 0;

    PBYTE pbBlob = NULL;

    SECURITY_STATUS         secStatus = ERROR_SUCCESS;

    int naming = 8;

    const wchar_t pszCurveName[] = BCRYPT_ECC_CURVE_SECP256R1;

    const wchar_t pszAlgName[] = BCRYPT_ECDSA_P256_ALGORITHM;

    //const wchar_t pszAlgNameList[sizeof(pszAlgName)][2] = { pszAlgName, BCRYPT_ECC_CURVE_NAME };
    BOOL bUseNamedCurveInterface;
    BOOL bSetCurveNameAsKeyProperty;
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        pszAlgName,
        NULL,
        0);
    if (!NT_SUCCESS(status))
    {
        printf("Error1 key 0x%x \n", status);
        goto cleanup;
    }

    //status = BCryptOpenAlgorithmProvider(
    //    &hAlg,
    //    pszCurveName,
    //    NULL,
    //    0);
    //if (!NT_SUCCESS(status))
    //{
    //    printf("Error openning algorithm provider 0x%x \n", status);
    //    goto cleanup;
    //}

    switch (naming)
    {
    case 1:
        bUseNamedCurveInterface = TRUE;
        status = BCryptSetProperty(hAlg, BCRYPT_ECC_CURVE_NAME, (PUCHAR)pszCurveName, (wcslen(pszCurveName) + 1) * sizeof(wchar_t), 0);
        if (!NT_SUCCESS(status)) {
            printf("Error2 key set property 0x%x \n", status);
            goto cleanup;
        }
        status = BCryptGenerateKeyPair(hAlg, &hkey, 256, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error2 key 0x%x \n", status);
            goto cleanup;
        }
        break;
    case 2:
        bUseNamedCurveInterface = TRUE;
        bSetCurveNameAsKeyProperty = TRUE;
        status = BCryptGenerateKeyPair(hAlg, &hkey, 0, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error2 key 0x%x \n", status);
            goto cleanup;
        }

        status = BCryptSetProperty(hkey, BCRYPT_ECC_CURVE_NAME, (PUCHAR)pszCurveName, (wcslen(pszCurveName) + 1) * sizeof(wchar_t), 0);
        if (!NT_SUCCESS(status)) {
            printf("Error2 key set property 0x%x \n", status);
            goto cleanup;
        }
        break;
    default:
        if (!NT_SUCCESS(status))
        {
            printf("Error1 key 0x%x \n", status);
            goto cleanup;
        }
        status = BCryptGenerateKeyPair(hAlg, &hkey, 256, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error2 key 0x%x \n", status);
            goto cleanup;
        }
        break;
    }

    status = BCryptFinalizeKeyPair(hkey, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error3 key 0x%x \n", status);
        goto cleanup;
    }




    //status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    //if (!NT_SUCCESS(status)) {
    //    printf("Error1 0x%x \n", status);
    //    goto cleanup;
    //}
    //status = BCryptGetProperty(hHashAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbDigest, sizeof(cbDigest), &cbResult, 0);
    //if (!NT_SUCCESS(status)) {
    //    printf("Error2 0x%x \n", status);
    //    goto cleanup;
    //}
    //status = BCryptCreateHash(hHashAlg, &hHash, NULL, 0, NULL, 0, 0);
    //if (!NT_SUCCESS(status)) {
    //    printf("Error3 0x%x \n", status);
    //    goto cleanup;
    //}
    static const  BYTE rgbMsg[] =
    {
        0x04, 0x87, 0xec, 0x66, 0xa8, 0xbf, 0x17, 0xa6,
        0xe3, 0x62, 0x6f, 0x1a, 0x55, 0xe2, 0xaf, 0x5e,
        0xbc, 0x54, 0xa4, 0xdc, 0x68, 0x19, 0x3e, 0x94,
    };
    //status = BCryptHashData(hHash, (PBYTE)rgbMsg, sizeof(rgbMsg), 0);
    //if (!NT_SUCCESS(status)) {
    //    printf("Error4 0x%x \n", status);
    //    goto cleanup;
    //}


    //status = BCryptFinishHash(hHash, pbHash, cbDigest, 0);
    //if (!NT_SUCCESS(status)) {
    //    printf("Error5 0x%x \n", status);
    //    goto cleanup;
    //}

    CrHash(status, hHashAlg, hHash, &cbDigest, cbResult, rgbMsg, pbHash);

    status = BCryptSignHash(hkey, NULL, pbHash, cbDigest, NULL, 0, &cbSignature, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error6 0x%x \n", status);
        goto cleanup;
    }
    PBYTE pbSignature = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbSignature);
    status = BCryptSignHash(hkey, NULL, pbHash, cbDigest, pbSignature, cbSignature, &cbSignature, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error7 0x%x \n", status);
        goto cleanup;
    }
    printf("signed \n");

    status = BCryptExportKey(hkey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &cbBlob, 0);
    if (!NT_SUCCESS(status))
    {
        printf("Error7 ex 0x%x \n", status);
        goto cleanup;
    }

    pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
    if (NULL == pbBlob)
    {
        status = STATUS_NO_MEMORY;
        goto cleanup;
    }

    status = BCryptExportKey(hkey, NULL, BCRYPT_ECCPUBLIC_BLOB, pbBlob, cbBlob, &cbResult, 0);
    if (!NT_SUCCESS(status))
    {
        printf("Error7 ex 2 0x%x \n", status);
        goto cleanup;
    }



    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hVerKey, pbBlob, cbBlob, 0);
    if (!NT_SUCCESS(status))
    {
        printf("Error7 ip 0x%x \n", status);
        goto cleanup;
    }

    //сделать verify key и оба освободить в коцне
    status = BCryptVerifySignature(hVerKey, NULL, pbHash, cbDigest, pbSignature, (ULONG)cbSignature, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error8 ver 0x%x \n", status);
        goto cleanup;
    }
    printf("Verified \n");
cleanup:
    if (hkey != NULL) {
        BCryptDestroyKey(hkey);
    }
    if (hkey != NULL) {
        BCryptDestroyKey(hVerKey);
    }
    if (hAlg != NULL) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
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






    return 1;
}
