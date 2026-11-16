#include <windows.h>
#include <cstdio>

typedef enum _DRX {
	Dr0,
	Dr1,
	Dr2,
	Dr3
} DRX, *PDRX;

// ----- Globals (declared once, before first use) ----------------------------
PVOID            g_VectorHandler   = NULL;               // VEH handle
CRITICAL_SECTION g_CriticalSection = { 0 };              // Critical section
PVOID            g_DetourFuncs[4]  = { 0 };              // Detour per Dr slot
PVOID            g_HookedAddrs[4]  = { 0 };              // Hooked address per Dr slot

// ----- Helpers --------------------------------------------------------------
BOOL ReportError(LPCTSTR Api, PVOID Unused) {
	(void)Unused;
	printf("[!] %s failed (error %lu)\n", Api, GetLastError());
	return FALSE;
}

static unsigned long long SetDr7Bits(unsigned long long CurrentDr7Register,
                                     int StartingBitPosition,
                                     int NmbrOfBitsToModify,
                                     unsigned long long NewBitValue) {
	unsigned long long mask = (1ULL << NmbrOfBitsToModify) - 1ULL;
	return (CurrentDr7Register & ~(mask << StartingBitPosition)) |
	       (NewBitValue << StartingBitPosition);
}

// Returns a pointer to the Dr0..Dr3 field of a context, or NULL for an invalid index
static DWORD64* GetDrRegister(PCONTEXT pCtx, DRX Drx) {
	switch (Drx) {
		case Dr0: return &pCtx->Dr0;
		case Dr1: return &pCtx->Dr1;
		case Dr2: return &pCtx->Dr2;
		case Dr3: return &pCtx->Dr3;
		default:  return NULL;
	}
}

// ----- Hardware breakpoint management ---------------------------------------
BOOL SetHardwareBreakingPnt(IN PVOID pAddress, IN PVOID fnHookFunc, IN DRX Drx) {

	if (!pAddress || !fnHookFunc)
		return FALSE;

	CONTEXT ThreadCtx = { 0 };
	ThreadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(GetCurrentThread(), &ThreadCtx))
		return ReportError(TEXT("GetThreadContext"), NULL);

	DWORD64* pDr = GetDrRegister(&ThreadCtx, Drx);
	if (!pDr)
		return FALSE;
	*pDr = (DWORD64)(ULONG_PTR)pAddress;

	// Enable the local breakpoint for this slot (Ln bit at position Drx*2)
	ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, Drx * 2, 1, 1);

	if (!SetThreadContext(GetCurrentThread(), &ThreadCtx))
		return ReportError(TEXT("SetThreadContext"), NULL);

	g_DetourFuncs[Drx] = fnHookFunc;
	g_HookedAddrs[Drx] = pAddress;
	return TRUE;
}

BOOL RemoveHardwareBreakingPnt(IN DRX Drx) {

	CONTEXT ThreadCtx = { 0 };
	ThreadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(GetCurrentThread(), &ThreadCtx))
		return ReportError(TEXT("GetThreadContext"), NULL);

	DWORD64* pDr = GetDrRegister(&ThreadCtx, Drx);
	if (!pDr)
		return FALSE;
	*pDr = 0;

	// Disable the local breakpoint for this slot
	ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, Drx * 2, 1, 0);

	if (!SetThreadContext(GetCurrentThread(), &ThreadCtx))
		return ReportError(TEXT("SetThreadContext"), NULL);

	g_DetourFuncs[Drx] = NULL;
	g_HookedAddrs[Drx] = NULL;
	return TRUE;
}

// ----- Argument access (x64 and x86) ----------------------------------------
VOID SetFunctionArgument(IN PCONTEXT pThreadCtx, IN ULONG_PTR uValue, IN DWORD dwParmIndex) {

#ifdef _WIN64
	// First 4 integer args in x64 are in RCX, RDX, R8, R9
	switch (dwParmIndex) {
		case 0x01: pThreadCtx->Rcx = uValue; return;
		case 0x02: pThreadCtx->Rdx = uValue; return;
		case 0x03: pThreadCtx->R8  = uValue; return;
		case 0x04: pThreadCtx->R9  = uValue; return;
		default:   break;
	}
	// Remaining args live on the stack above the return address
	*(ULONG_PTR*)(pThreadCtx->Rsp + (dwParmIndex * sizeof(PVOID))) = uValue;
#else
	*(DWORD_PTR*)(pThreadCtx->Esp + (dwParmIndex * sizeof(PVOID))) = uValue;
#endif
}

ULONG_PTR GetFunctionArgument(IN PCONTEXT pThreadCtx, IN DWORD dwParmIndex) {

#ifdef _WIN64
	switch (dwParmIndex) {
		case 0x01: return pThreadCtx->Rcx;
		case 0x02: return pThreadCtx->Rdx;
		case 0x03: return pThreadCtx->R8;
		case 0x04: return pThreadCtx->R9;
		default:   break;
	}
	return *(ULONG_PTR*)(pThreadCtx->Rsp + (dwParmIndex * sizeof(PVOID)));
#else
	return *(DWORD_PTR*)(pThreadCtx->Esp + (dwParmIndex * sizeof(PVOID)));
#endif
}

#define GETPARM_1(CTX) (GetFunctionArgument(CTX, 0x1))
#define GETPARM_2(CTX) (GetFunctionArgument(CTX, 0x2))
#define GETPARM_3(CTX) (GetFunctionArgument(CTX, 0x3))
#define GETPARM_4(CTX) (GetFunctionArgument(CTX, 0x4))

#define SETPARM_1(CTX, VALUE) (SetFunctionArgument(CTX, (ULONG_PTR)(VALUE), 0x1))
#define SETPARM_2(CTX, VALUE) (SetFunctionArgument(CTX, (ULONG_PTR)(VALUE), 0x2))
#define SETPARM_3(CTX, VALUE) (SetFunctionArgument(CTX, (ULONG_PTR)(VALUE), 0x3))
#define SETPARM_4(CTX, VALUE) (SetFunctionArgument(CTX, (ULONG_PTR)(VALUE), 0x4))

// ----- Vectored exception handler -------------------------------------------
// Runs when a hardware breakpoint fires (reported as EXCEPTION_SINGLE_STEP).
LONG WINAPI VectorHandler(IN PEXCEPTION_POINTERS pExceptionInfo) {

	if (pExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
		return EXCEPTION_CONTINUE_SEARCH;

	PVOID pFaultAddr = pExceptionInfo->ExceptionRecord->ExceptionAddress;

	for (int i = 0; i < 4; i++) {
		if (g_HookedAddrs[i] && g_HookedAddrs[i] == pFaultAddr) {
			PCONTEXT pCtx = pExceptionInfo->ContextRecord;

			if (g_DetourFuncs[i])
				((VOID(*)(PCONTEXT))g_DetourFuncs[i])(pCtx);

			// Resume flag: don't re-trigger the breakpoint on this same instruction
			pCtx->EFlags |= (1 << 16);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

// ----- Setup / teardown -----------------------------------------------------
BOOL InitializeHardwareBPVariables() {

	RtlSecureZeroMemory(g_DetourFuncs, sizeof(g_DetourFuncs));
	RtlSecureZeroMemory(g_HookedAddrs, sizeof(g_HookedAddrs));

	if (!g_CriticalSection.DebugInfo)
		InitializeCriticalSection(&g_CriticalSection);

	if (!g_VectorHandler) {
		if ((g_VectorHandler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)VectorHandler)) == NULL)
			return ReportError(TEXT("AddVectoredExceptionHandler"), NULL);
	}

	return (g_VectorHandler != NULL && g_CriticalSection.DebugInfo != NULL);
}

VOID UnintializeHardwareBPVariables() {

	// Remove breakpoints
	for (int i = 0; i < 4; i++)
		RemoveHardwareBreakingPnt((DRX)i);

	if (g_CriticalSection.DebugInfo)
		DeleteCriticalSection(&g_CriticalSection);

	if (g_VectorHandler) {
		RemoveVectoredExceptionHandler(g_VectorHandler);
		g_VectorHandler = NULL;
	}

	RtlSecureZeroMemory(g_DetourFuncs, sizeof(g_DetourFuncs));
	RtlSecureZeroMemory(g_HookedAddrs, sizeof(g_HookedAddrs));
}

// ----- Detour ---------------------------------------------------------------
VOID MessageBoxADetour(IN PCONTEXT pThreadCtx) {

	printf("[i] MessageBoxA's Old Parameters: \n");
	printf("\t> %s \n", (char*)GETPARM_2(pThreadCtx));
	printf("\t> %s \n", (char*)GETPARM_3(pThreadCtx));

	SETPARM_2(pThreadCtx, "This Is The Hook");
	SETPARM_3(pThreadCtx, "MessageBoxADetour");
	SETPARM_4(pThreadCtx, (MB_OK | MB_ICONEXCLAMATION));
}

// ----- Main -----------------------------------------------------------------
int main() {

	if (!InitializeHardwareBPVariables())
		return -1;

	// [ NOT HOOKED ]
	MessageBoxA(NULL, "This Is A Normal MsgBoxA Call (0)", "Normal", MB_OK);

	printf("[i] Installing Hooks ... ");
	if (!SetHardwareBreakingPnt((PVOID)MessageBoxA, (PVOID)MessageBoxADetour, Dr0))
		return -1;
	printf("[+] DONE \n");

	// [ HOOKED ]
	MessageBoxA(NULL, "This Wont Execute", "Will it ?", MB_OK);

	printf("[i] Uninstalling Hooks ... ");
	if (!RemoveHardwareBreakingPnt(Dr0))
		return -1;
	printf("[+] DONE \n");

	// [ NOT HOOKED ]
	MessageBoxA(NULL, "This Is A Normal MsgBoxA Call (1)", "Normal", MB_OK);

	UnintializeHardwareBPVariables();
	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}
