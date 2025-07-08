#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ncrypt.h>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")


#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)












//#define CPUUINT_ASSERT_MESSAGE(message, condition, status1, status2) if (!condition) { printf("%s %x %x  \n", message, status1, status2); goto cleanup;}




#define CPUUINT_ASSERT_MESSAGE(message, condition) if (!condition) { printf("%s  \n", message); goto cleanup;}

void PrintBytes(PBYTE data, DWORD size) {
    if (data == NULL || size == 0) {
        return;
    }
    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 2 == 0) {
            printf(" ");
        }
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}


int main() {
    printf("started \n");

    NTSTATUS status = 0;
    NTSTATUS status1 = 0;
    NTSTATUS status2 = 0;
    BCRYPT_ALG_HANDLE hAlg = 0;
    BCRYPT_KEY_HANDLE hkeyC = 0;

    NCRYPT_KEY_HANDLE hkey = 0;

    NCRYPT_KEY_HANDLE hkeyB = 0;

    NCRYPT_KEY_HANDLE hkeyB1 = 0;

    NCRYPT_KEY_HANDLE hkeyB2 = 0;

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
    BOOL standart = FALSE;
    while (i < 6) {
        status = BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_ECDH_P256_ALGORITHM,
            NULL,
            0);
        standart = FALSE;
        if (i == 0 || i == 2 || i == 3) {
            standart = TRUE;
        }
        printf("r this is value of standart bool %x \n", standart);
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

        status = NCryptSetProperty(hkey, BCRYPT_ECC_CURVE_NAME, pszAlgNameList[i], (wcslen(pszAlgNameList[i]) + 1) * sizeof(wchar_t), 0);
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

        status = NCryptSetProperty(hkeyB, BCRYPT_ECC_CURVE_NAME, pszAlgNameList[i], (wcslen(pszAlgNameList[i]) + 1) * sizeof(wchar_t), 0);
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

































        PrintBytes(pbBlob, cbBlob);


        //status = NCryptImportKey(hProv, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, &hkeyB, pbBlob, cbBlob, 0);
        //if (!NT_SUCCESS(status)) {
        //    printf("Error importing key 0x%x", status);
        //    goto cleanup;
        //}

        //NCRYPT_SECRET_HANDLE secret = 0;
        //status = NCryptSecretAgreement(hkey, hkeyB, &secret, 0);
        //if (!NT_SUCCESS(status)) {
        //    printf("Error on agreement 0x%x \n", status);
        //    goto cleanup;
        //}
        //BCryptDestroySecret(secret);
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


        PBYTE pbBlob1 = NULL;
        DWORD cbBlob1 = 0;
        PBYTE pbBlob2 = NULL;
        DWORD cbBlob2 = 0;

        status = NCryptExportKey(hkeyB, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, NULL, NULL, 0, &cbBlob1, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error exporting key 0x%x \n", status);
            goto cleanup;
        }
        pbBlob1 = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob1);
        status = NCryptExportKey(hkeyB, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, NULL, pbBlob1, cbBlob1, &cbBlob1, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error exporting2 key 0x%x", status);
            goto cleanup;
        }

        printf("FULLPUBLIC \n");
        PrintBytes(pbBlob1, cbBlob1);







        status = NCryptExportKey(hkeyB, NULL, BCRYPT_PUBLIC_KEY_BLOB, NULL, NULL, 0, &cbBlob2, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error exporting key 0x%x \n", status);
            goto cleanup;
        }
        pbBlob2 = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob2);
        
        status = NCryptExportKey(hkeyB, NULL, BCRYPT_PUBLIC_KEY_BLOB, NULL, pbBlob2, cbBlob2, &cbBlob2, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error exporting2 key 0x%x", status);
            goto cleanup;
        }
        

        printf("PUBLIC_KEY \n");
        PrintBytes(pbBlob2, cbBlob2);

        
        //CPUUINT_ASSERT_MESSAGE("PuBLIC key blob size is not equal to PUBLIC BLOB \n ", cbBlob2==cbBlob, status);
        //CPUUINT_ASSERT_MESSAGE("PuBLIC key blob is not equal to PUBLIC BLOB \n ", memcmp(pbBlob, pbBlob2, cbBlob)==0, status);
        //CPUUINT_ASSERT_MESSAGE("PuBLIC key blob is not equal to PUBLIC BLOB \n ", memcmp(pbBlob, pbBlob2, cbBlob) == 0);
        //CPUUINT_ASSERT_MESSAGE("PuBLIC key blob size is not equal to FULLPUBLIC BLOB \n ", cbBlob2 == cbBlob1, status);
        //CPUUINT_ASSERT_MESSAGE("PuBLIC key blob is not equal to FULLPUBLIC BLOB \n ", memcmp(pbBlob1, pbBlob2, cbBlob1) == 0, status);

        status = NCryptImportKey(hProv, NULL, BCRYPT_PUBLIC_KEY_BLOB, NULL, &hkeyB, pbBlob2, cbBlob2, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error importing1 key 0x%x", status);
            goto cleanup;
        }
        status1 = NCryptImportKey(hProv, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, &hkeyB, pbBlob2, cbBlob2, 0);
        status2 = NCryptImportKey(hProv, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, NULL, &hkeyB, pbBlob2, cbBlob2, 0);
        //CPUUINT_ASSERT_MESSAGE("IMPORTING ECCFULLPUBLIC TO PUBLICK KEY BLOB gone wrong \n ", NT_SUCCESS(status2));
        // checking results of imports when named and when standart
        //standart first
        CPUUINT_ASSERT_MESSAGE("status 1 gone wrong when it shouldn't \n", (NT_SUCCESS(status1)||!standart));
        CPUUINT_ASSERT_MESSAGE("status 2 gone right when it shouldn't \n", (!NT_SUCCESS(status2) ||!standart));
        // named after
        CPUUINT_ASSERT_MESSAGE("status 1 gone right when it shouldn't \n", (!NT_SUCCESS(status1) || standart));
        CPUUINT_ASSERT_MESSAGE("status 2 gone wrongt when it shouldn't \n", (NT_SUCCESS(status2) || standart));
        /*CPUUINT_ASSERT_MESSAGE("IMPORTING ECCFULLPUBLIC TO PUBLICK KEY BLOB gone wrong \n ", NT_SUCCESS(status2 = NCryptImportKey(hProv, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, NULL, &hkeyB, pbBlob2, cbBlob2, 0)), status);*/
        

        /*CPUUINT_ASSERT_MESSAGE("Both imports gone similarly ", status1 ==  status2);*/
        // FULLPUBLIC na imenovannuh sovpadaet
        // PUBLIc na standartnuh sovpadaet
        NCRYPT_SECRET_HANDLE secret2 = 0;
        status = NCryptImportKey(hProv, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, NULL, &hkeyB, pbBlob1, cbBlob1, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error importing2 key 0x%x", status);
            goto cleanup;
        }
        status = NCryptSecretAgreement(hkey, hkeyB, &secret2, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error on agreement1 0x%x \n", status);
            goto cleanup;
        }
        BCryptDestroySecret(secret2);
        NCRYPT_SECRET_HANDLE secret1 = 0;
        status = NCryptSecretAgreement(hkey, hkeyB, &secret1, 0);
        if (!NT_SUCCESS(status)) {
            printf("Error on agreement2 0x%x \n", status);
            goto cleanup;
        }
        BCryptDestroySecret(secret1);

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

