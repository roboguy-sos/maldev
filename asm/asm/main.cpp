#include <cstdio>
#include <windows.h>

extern "C" {
    DWORD wNtAllocateVirtualMemory = 0;
    UINT_PTR sysAddrNtAllocateVirtualMemory = 0;

    NTSTATUS NTAPI NtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG PageProtection
    );
}



int main() {
    HANDLE p = (HANDLE)-1;
    char pay[] = "";
    PVOID addr = nullptr;
    SIZE_T s = sizeof(pay);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemory + 4))[0];
    sysAddrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;

    NTSTATUS st = NtAllocateVirtualMemory(p, &addr, (ULONG_PTR)0, &s, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    printf("status %lu addr %p\n", st, addr);
}