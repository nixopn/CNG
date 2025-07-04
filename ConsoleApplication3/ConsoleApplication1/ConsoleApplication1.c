#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ncrypt.h>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")

#define CPUUINT_ASSERT_MESSAGE(message, condition, status) if (!condition) { printf("%s %x", message, status); goto cleanup;}


#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

void PrintBytes(PBYTE data, DWORD size) {
    if (data == NULL || size == 0) {
        return;
    }
    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
        if ((i+1) % 2 == 0) {
            printf(" ");
        }
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}



void check(NTSTATUS status, BCRYPT_KEY_HANDLE hkey, BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE hkeyB, BCRYPT_SECRET_HANDLE secret, wchar_t pszCurveName[]) {
    printf("started \n");
    for (int i = 0; i < wcslen(pszCurveName); i++) {
        printf("%c", pszCurveName[i]);
    }
    printf("\n");
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_ECDH_ALGORITHM,
        NULL,
        0);
    CPUUINT_ASSERT_MESSAGE("Error opening algorithm proider", NT_SUCCESS(status), status);
    status = BCryptSetProperty(hAlg, BCRYPT_ECC_CURVE_NAME, pszCurveName, (wcslen(pszCurveName) + 1) * sizeof(wchar_t), 0);
    CPUUINT_ASSERT_MESSAGE("Error setting property", NT_SUCCESS(status), status);
    status = BCryptGenerateKeyPair(hAlg, &hkey, 0, 0);
    CPUUINT_ASSERT_MESSAGE("Error generating key pair A", NT_SUCCESS(status), status);


    status = BCryptFinalizeKeyPair(hkey, 0);
    CPUUINT_ASSERT_MESSAGE("Error finalizing key pai A", NT_SUCCESS(status), status);

    BCryptCloseAlgorithmProvider(hAlg, 0);

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_ECDH_ALGORITHM,
        NULL,
        0);
    CPUUINT_ASSERT_MESSAGE("Error opening algorithm provider B", NT_SUCCESS(status), status);

    status = BCryptGenerateKeyPair(hAlg, &hkeyB, 0, 0);
    CPUUINT_ASSERT_MESSAGE("Error generating key pair B", NT_SUCCESS(status), status);

    status = BCryptSetProperty(hkeyB, BCRYPT_ECC_CURVE_NAME, (PUCHAR)pszCurveName, (wcslen(pszCurveName) + 1) * sizeof(wchar_t), 0);
    CPUUINT_ASSERT_MESSAGE("Error setting property on key pair B", NT_SUCCESS(status), status);

    status = BCryptFinalizeKeyPair(hkeyB, 0);
    CPUUINT_ASSERT_MESSAGE("Error finalizing key pair B", NT_SUCCESS(status), status);

    DWORD cbBlob = 0;
    PBYTE pbBlob = NULL;
    DWORD cbBlob1 = 0;
    PBYTE pbBlob1 = NULL;
    DWORD ResultLength;
    DWORD cbBlob2 = 0;
    PBYTE pbBlob2 = NULL;
    // FULL PUBLIC
    status = BCryptExportKey(hkeyB, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, NULL, 0, &cbBlob, 0);
    CPUUINT_ASSERT_MESSAGE("Error exporting key first step of exporting", NT_SUCCESS(status), status);

    pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
    CPUUINT_ASSERT_MESSAGE("Error allocating heap", pbBlob != NULL, status);

    status = BCryptExportKey(hkeyB, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, pbBlob, cbBlob, &ResultLength, 0);
    CPUUINT_ASSERT_MESSAGE("Error exporting key second step of exporting", NT_SUCCESS(status), status);



    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, &hkeyB, pbBlob, cbBlob, 0);
    CPUUINT_ASSERT_MESSAGE("Error importing key pair", NT_SUCCESS(status), status);

    printf("FULL PUBLIC \n");
    PrintBytes(pbBlob, cbBlob);
    //PUBLIC KEY
    status = BCryptExportKey(hkeyB, NULL, BCRYPT_PUBLIC_KEY_BLOB, NULL, 0, &cbBlob1, 0);
    CPUUINT_ASSERT_MESSAGE("Error exporting key first step of exporting", NT_SUCCESS(status), status);

    pbBlob1 = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob1);
    CPUUINT_ASSERT_MESSAGE("Error allocating heap", pbBlob1 != NULL, status);

    status = BCryptExportKey(hkeyB, NULL, BCRYPT_PUBLIC_KEY_BLOB, pbBlob1, cbBlob1, &ResultLength, 0);
    CPUUINT_ASSERT_MESSAGE("Error exporting key second step of exporting", NT_SUCCESS(status), status);



    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_PUBLIC_KEY_BLOB, &hkeyB, pbBlob1, cbBlob1, 0);
    CPUUINT_ASSERT_MESSAGE("Error importing key pair", NT_SUCCESS(status), status);

    printf("PUBLIC KEY \n");
    PrintBytes(pbBlob1, cbBlob1);

    //PUBLIC
        status = BCryptExportKey(hkeyB, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &cbBlob2, 0);
        CPUUINT_ASSERT_MESSAGE("Error exporting key first step of exporting", NT_SUCCESS(status), status);

    pbBlob2 = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob2);
    CPUUINT_ASSERT_MESSAGE("Error allocating heap", pbBlob2 != NULL, status);

    status = BCryptExportKey(hkeyB, NULL, BCRYPT_ECCPUBLIC_BLOB, pbBlob2, cbBlob2, &ResultLength, 0);
    CPUUINT_ASSERT_MESSAGE("Error exporting key second step of exporting", NT_SUCCESS(status), status);

    printf("PUBLIC \n");
    PrintBytes(pbBlob2, cbBlob2);





    status = BCryptSecretAgreement(hkey, hkeyB, &secret, 0);
    CPUUINT_ASSERT_MESSAGE("Error opening algorithm proider", NT_SUCCESS(status), status);

    //PBYTE dk = NULL;
    //DWORD cdk = 0;
    //DWORD rcdk = 0;
    //status = NCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, NULL, dk, cdk, rcdk, 0);
    //if (!NT_SUCCESS(status))
    //{
    //    printf("Error7 ip 0x%x \n", status);
    //    goto cleanup;
    //}

    BCryptDestroySecret(secret);


    printf("Agreed \n");
    
    cleanup:
        if (hkey != NULL) {
            BCryptDestroyKey(hkey);
        }
        if (hkeyB != NULL) {
            BCryptDestroyKey(hkeyB);
        }
        if (hAlg != NULL) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }
        if (secret != NULL) {
            BCryptDestroySecret(secret);
        }
}

int main() {
    printf("started \n");
    NTSTATUS status = 0;
    BCRYPT_KEY_HANDLE hkey = 0;
    BCRYPT_ALG_HANDLE       hAlg = 0;
    BCRYPT_KEY_HANDLE       hkeyB = 0;
    BCRYPT_SECRET_HANDLE secret = 0;

    int naming = 8;

    const wchar_t pszCurveName[] = BCRYPT_ECC_CURVE_SECP256R1;

    const wchar_t pszAlgName[] = BCRYPT_ECDH_P256_ALGORITHM;


    
    const wchar_t *pszAlgNameList[] = 
    { 
        BCRYPT_ECC_CURVE_SECP256R1 , 
        BCRYPT_ECC_CURVE_SECP256K1, 
        BCRYPT_ECC_CURVE_SECP384R1, 
        BCRYPT_ECC_CURVE_SECP521R1, 
        BCRYPT_ECC_CURVE_BRAINPOOLP160R1, 
        BCRYPT_ECC_CURVE_25519 
    };

    BOOL bUseNamedCurveInterface;
    BOOL bSetCurveNameAsKeyProperty;

   

    int i = 0;

    while (i < 6) {
        check(status, hkey, hAlg, hkeyB, secret, pszAlgNameList[i]);
        i++;
    }



cleanup:
    if (hkey != NULL) {
        BCryptDestroyKey(hkey);
    }
    if (hkeyB != NULL) {
        BCryptDestroyKey(hkeyB);
    }
    if (hAlg != NULL) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if (secret != NULL) {
        BCryptDestroySecret(secret);
    }

















    
    return 1;
}
