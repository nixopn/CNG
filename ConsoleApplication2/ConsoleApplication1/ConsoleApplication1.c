#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ncrypt.h>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")


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
    if (!NT_SUCCESS(status))
    {
        printf("Error1 key 0x%x \n", status);
        goto cleanup;
    }
    status = BCryptSetProperty(hAlg, BCRYPT_ECC_CURVE_NAME, pszCurveName, (wcslen(pszCurveName) + 1) * sizeof(wchar_t), 0);
    if (!NT_SUCCESS(status)) {
        printf("Error2 key set property 0x%x \n", status);
        goto cleanup;
    }
    status = BCryptGenerateKeyPair(hAlg, &hkey, 0, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error2 key 0x%x \n", status);
        goto cleanup;
    }


    status = BCryptFinalizeKeyPair(hkey, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error3 key 0x%x \n", status);
        goto cleanup;
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_ECDH_ALGORITHM,
        NULL,
        0);
    if (!NT_SUCCESS(status))
    {
        printf("Error1 key 0x%x \n", status);
        goto cleanup;
    }

    status = BCryptGenerateKeyPair(hAlg, &hkeyB, 0, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error2 key 0x%x \n", status);
        goto cleanup;
    }

    status = BCryptSetProperty(hkeyB, BCRYPT_ECC_CURVE_NAME, (PUCHAR)pszCurveName, (wcslen(pszCurveName) + 1) * sizeof(wchar_t), 0);
    if (!NT_SUCCESS(status)) {
        printf("Error2 key set property 0x%x \n", status);
        goto cleanup;
    }

    status = BCryptFinalizeKeyPair(hkeyB, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error3 key 0x%x \n", status);
        goto cleanup;
    }

    DWORD cbBlob = 0;
    PBYTE pbBlob = NULL;
    DWORD cbBlob1 = 0;
    PBYTE pbBlob1 = NULL;
    DWORD ResultLength;
    DWORD cbBlob2 = 0;
    PBYTE pbBlob2 = NULL;
    // FULL PUBLIC
    status = BCryptExportKey(hkeyB, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, NULL, 0, &cbBlob, 0);
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

    status = BCryptExportKey(hkeyB, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, pbBlob, cbBlob, &ResultLength, 0);
    if (!NT_SUCCESS(status))
    {
        printf("Error7 ex 2 0x%x \n", status);
        goto cleanup;
    }



    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, &hkeyB, pbBlob, cbBlob, 0);
    if (!NT_SUCCESS(status))
    {
        printf("Error7 ip 0x%x \n", status);
        goto cleanup;
    }
    printf("FULL PUBLIC \n");
    PrintBytes(pbBlob, cbBlob);
    //PUBLIC KEY
    status = BCryptExportKey(hkeyB, NULL, BCRYPT_PUBLIC_KEY_BLOB, NULL, 0, &cbBlob1, 0);
    if (!NT_SUCCESS(status))
    {
        printf("Error7 ex 0x%x \n", status);
        goto cleanup;
    }

    pbBlob1 = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob1);
    if (NULL == pbBlob)
    {
        status = STATUS_NO_MEMORY;
        goto cleanup;
    }

    status = BCryptExportKey(hkeyB, NULL, BCRYPT_PUBLIC_KEY_BLOB, pbBlob1, cbBlob1, &ResultLength, 0);
    if (!NT_SUCCESS(status))
    {
        printf("Error7 ex 2 0x%x \n", status);
        goto cleanup;
    }



    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_PUBLIC_KEY_BLOB, &hkeyB, pbBlob1, cbBlob1, 0);
    if (!NT_SUCCESS(status))
    {
        printf("Error7 ip 0x%x \n", status);
        goto cleanup;
    }
    printf("PUBLIC KEY \n");
    PrintBytes(pbBlob1, cbBlob1);

    //PUBLIC
        status = BCryptExportKey(hkeyB, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &cbBlob2, 0);
    if (!NT_SUCCESS(status))
    {
        printf("Error7 ex 0x%x \n", status);
        goto cleanup;
    }

    pbBlob2 = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob2);
    if (NULL == pbBlob)
    {
        status = STATUS_NO_MEMORY;
        goto cleanup;
    }

    status = BCryptExportKey(hkeyB, NULL, BCRYPT_ECCPUBLIC_BLOB, pbBlob2, cbBlob2, &ResultLength, 0);
    if (!NT_SUCCESS(status))
    {
        printf("Error7 ex 2 0x%x \n", status);
        goto cleanup;
    }
    printf("PUBLIC \n");
    PrintBytes(pbBlob2, cbBlob2);





    status = BCryptSecretAgreement(hkey, hkeyB, &secret, 0);
    if (!NT_SUCCESS(status)) {
        printf("Error on agreement 0x%x \n", status);
        goto cleanup;
    }

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
