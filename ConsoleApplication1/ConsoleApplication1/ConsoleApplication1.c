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
    BCRYPT_KEY_HANDLE hkey = 0;
    BCRYPT_KEY_HANDLE       hTmpKey = 0;
    BCRYPT_ALG_HANDLE       AlgHandle = 0;

    BCRYPT_ALG_HANDLE       HashAlgHandle = 0;
    BCRYPT_HASH_HANDLE      HashHandle = 0;


    DWORD                   HashDigestLength = 0;

    DWORD                   ResultLength = 0;

    PBYTE                   pbHash = NULL,
        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, HashDigestLength);
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, HashDigestLength);

    PBYTE cbSignature = NULL;

    DWORD cbBlob = 0;

    PBYTE pbBlob = NULL;

    SECURITY_STATUS         secStatus = ERROR_SUCCESS;

    int naming = 8;

    const wchar_t aaaaaaaa[] = BCRYPT_ECC_CURVE_SECP256R1;

    switch (naming)
    {
    case 1:
        status = BCryptOpenAlgorithmProvider(
            &AlgHandle,
            BCRYPT_ECDSA_ALGORITHM,
            NULL,
            0);
        if (!NT_SUCCESS(status))
        {
            printf("Error1 key 0x%x \n", status);
            goto cleanup;
        }
        status = BCryptSetProperty(AlgHandle, BCRYPT_ECC_CURVE_NAME, (PUCHAR)aaaaaaaa, (wcslen(aaaaaaaa) + 1) * sizeof(wchar_t), 0);
        if (!NT_SUCCESS(status)) {
            printf("Error2 key set property 0x%x \n", status);
            goto cleanup;
        }
        status = BCryptGenerateKeyPair(AlgHandle, &hkey, 256, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error2 key 0x%x \n", status);
            goto cleanup;
        }
        break;
    case 2:
        status = BCryptOpenAlgorithmProvider(
            &AlgHandle,
            BCRYPT_ECDSA_ALGORITHM,
            NULL,
            0);
        if (!NT_SUCCESS(status))
        {
            printf("Error1 key 0x%x \n", status);
            goto cleanup;
        }



        status = BCryptGenerateKeyPair(AlgHandle, &hkey, 0, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error2 key 0x%x \n", status);
            goto cleanup;
        }

        status = BCryptSetProperty(hkey, BCRYPT_ECC_CURVE_NAME, (PUCHAR)aaaaaaaa, (wcslen(aaaaaaaa) + 1) * sizeof(wchar_t), 0);
        if (!NT_SUCCESS(status)) {
            printf("Error2 key set property 0x%x \n", status);
            goto cleanup;
        }



        break;
    default:
        status = BCryptOpenAlgorithmProvider(
            &AlgHandle,
            BCRYPT_ECDSA_P256_ALGORITHM,
            NULL,
            0);
        if (!NT_SUCCESS(status))
        {
            printf("Error1 key 0x%x \n", status);
            goto cleanup;
        }
        status = BCryptGenerateKeyPair(AlgHandle, &hkey, 256, 0);
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



    status = BCryptOpenAlgorithmProvider(&HashAlgHandle, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error1 0x%x \n", status);
        goto cleanup;
    }
    status = BCryptGetProperty(HashAlgHandle, BCRYPT_HASH_LENGTH, (PBYTE)&HashDigestLength, sizeof(HashDigestLength), &ResultLength, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error2 0x%x \n", status);
        goto cleanup;
    }
    status = BCryptCreateHash(HashAlgHandle, &HashHandle, NULL, 0, NULL, 0, 0);
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
    status = BCryptHashData(HashHandle, (PBYTE)rgbMsg, sizeof(rgbMsg), 0);
    if (!NT_SUCCESS(status)) {
        printf("Error4 0x%x \n", status);
        goto cleanup;
    }


    status = BCryptFinishHash(HashHandle, pbHash, HashDigestLength, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error5 0x%x \n", status);
        goto cleanup;
    }


    status = BCryptSignHash(hkey, NULL, pbHash, HashDigestLength, NULL, 0, &cbSignature, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error6 0x%x \n", status);
        goto cleanup;
    }
    PBYTE pbSignature = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbSignature);
    status = BCryptSignHash(hkey, NULL, pbHash, HashDigestLength, pbSignature, cbSignature, &cbSignature, 0);
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

    status = BCryptExportKey(hkey, NULL, BCRYPT_ECCPUBLIC_BLOB, pbBlob, cbBlob, &ResultLength, 0);
    if (!NT_SUCCESS(status))
    {
        printf("Error7 ex 2 0x%x \n", status);
        goto cleanup;
    }



    status = BCryptImportKeyPair(AlgHandle, NULL, BCRYPT_ECCPUBLIC_BLOB, &hkey, pbBlob, cbBlob, 0);
    if (!NT_SUCCESS(status))
    {
        printf("Error7 ip 0x%x \n", status);
        goto cleanup;
    }

    //сделать verify key и оба освободить в коцне
    status = BCryptVerifySignature(hkey, NULL, pbHash, HashDigestLength, pbSignature, (ULONG)cbSignature, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error8 ver 0x%x \n", status);
        goto cleanup;
    }
    printf("Verified \n");
cleanup:
    /*       if (hkey != NULL) {
               BcryptDestroyKey(hkey);
           }*/
    if (AlgHandle != NULL) {
        BCryptCloseAlgorithmProvider(AlgHandle, 0);
    }

    if (HashAlgHandle != NULL)
    {
        BCryptCloseAlgorithmProvider(HashAlgHandle, 0);
    }

    if (HashHandle != NULL)
    {
        BCryptDestroyHash(HashHandle);
    }

    if (pbHashObject != NULL)
    {
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    }

    if (pbHash != NULL)
    {
        HeapFree(GetProcessHeap(), 0, pbHash);
    }






    return 1;
}

