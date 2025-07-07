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
    BCRYPT_ALG_HANDLE hAlg = 0;
    BCRYPT_KEY_HANDLE hkeyC = 0;

    NCRYPT_KEY_HANDLE hkey = 0;

    NCRYPT_KEY_HANDLE hkeyB = 0;

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

    const wchar_t pszAlgName[] = BCRYPT_ECDH_P256_ALGORITHM;

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
    int i = 0;
    while (i < 6) {
        status = BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_ECDH_P256_ALGORITHM,
            NULL,
            0);
        if (!NT_SUCCESS(status))
        {
            printf("Error1 key 0x%x \n", status);
            goto cleanup;
        }

        status = BCryptGenerateKeyPair(hAlg, &hkeyC, 0, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error2 key 0x%x \n", status);
            goto cleanup;
        }


        status = BCryptFinalizeKeyPair(hkeyC, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error3 key 0x%x \n", status);
            goto cleanup;
        }

        NCryptDeleteKey(hkey, 0);
        printf("%d \n", i);
        status = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error1 0x%x \n", status);
            goto cleanup;
        }

        status = NCryptCreatePersistedKey(hProv, &hkey, BCRYPT_ECDH_ALGORITHM, keyName, AT_SIGNATURE, NCRYPT_OVERWRITE_KEY_FLAG);
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

        status = NCryptCreatePersistedKey(hProv, &hkeyB, BCRYPT_ECDH_ALGORITHM, keyName, AT_SIGNATURE, NCRYPT_OVERWRITE_KEY_FLAG);
        if (!NT_SUCCESS(status)) {
            printf("Error2 0x%x \n", status);
            goto cleanup;
        }

        status = NCryptSetProperty(hkeyB, BCRYPT_ECC_CURVE_NAME, BCRYPT_ECC_CURVE_SECP256R1, (wcslen(BCRYPT_ECC_CURVE_SECP256R1) + 1) * sizeof(wchar_t), 0);
        if (!NT_SUCCESS(status)) {
            printf("Error2 set property 0x%x \n", status);
            goto cleanup;
        }
        status = NCryptFinalizeKey(hkeyB, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error3 0x%x \n", status);
            goto cleanup;
        }


        //cbBlob = 0;
        //pbBlob = NULL;
        DWORD ResultLength;
        status = NCryptExportKey(hkeyB, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, &cbBlob, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error exporting key 0x%x \n", status);
            goto cleanup;
        }
        pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
        status = NCryptExportKey(hkeyB, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, pbBlob, cbBlob, &cbBlob, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error exporting2 key 0x%x", status);
            goto cleanup;
        }



        status = NCryptImportKey(hProv, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, &hkeyB, pbBlob, cbBlob, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error importing key 0x%x", status);
            goto cleanup;
        }

        NCRYPT_SECRET_HANDLE secret = 0;
        status = NCryptSecretAgreement(hkey, hkeyB, &secret, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error on agreement 0x%x \n", status);
            goto cleanup;
        }
        BCryptDestroySecret(secret);
        printf("signed \n");
        NCRYPT_SECRET_HANDLE secret3 = 0;
        //status = NCryptSecretAgreement(hkey, hkeyB, &secret3, 0);
        //if (!NT_SUCCESS(status)) {
        //    printf("Error on agreement 3  0x%x \n", status);
        //    goto cleanup;
        //}
        //NCRYPT_SECRET_HANDLE secret2 = 0;
        //status = NCryptSecretAgreement(hkeyC, hkeyB, &secret2, 0);
        //if (!NT_SUCCESS(status)) {
        //    printf("Error on agreement 2 0x%x \n", status);
        //    goto cleanup;
        //}
        printf("Agreed \n");

        //status = NCryptExportKey(hkey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, &cbBlob, 0);
        //if (!NT_SUCCESS(status)) {
        //    printf("Error exporting key 0x%x \n", status);
        //    goto cleanup;
        //}
        //pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
        //status = NCryptExportKey(hkey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, pbBlob, cbBlob, &cbBlob, 0);
        //if (!NT_SUCCESS(status)) {
        //    printf("Error exporting2 key 0x%x", status);
        //    goto cleanup;
        //}
        //status = BCryptOpenAlgorithmProvider(
        //    &hSignAlg,
        //    BCRYPT_ECDSA_P256_ALGORITHM,
        //    NULL,
        //    0);
        //if (!NT_SUCCESS(status)) {
        //    printf("Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        //    goto cleanup;
        //}
        //status = BCryptImportKeyPair(hSignAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hVerKey, pbBlob, cbBlob, 0);
        //if (!NT_SUCCESS(status)) {
        //    printf("Error importing key 0x%x", status);
        //    goto cleanup;
        //}



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

        /*if (pbHash != NULL)
        {
            HeapFree(GetProcessHeap(), 0, pbHash);
        }*/

        // можно Blob в Bcrypt закидывть и оттуда согласовывать с NCryptом обратно - нельзя.
        if (hProv != NULL) {
            NCryptFreeObject(hProv);

        }

        i++;
    }


    return 1;
}

