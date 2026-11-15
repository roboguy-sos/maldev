#include <cstdio>
#include <cstring>
#include <errhandlingapi.h>
#include <memoryapi.h>
#include <minwindef.h>
#include <windows.h>
#include <winnt.h>
#include "help.h"

int wmain(){
    HMODULE adv = LoadLibraryA("advapi32.dll");
    printf("advapi address %p\n", adv);

    char pay[] = "racer101 was here!";
    DWORD sp = sizeof(pay);
    DWORD old = 0;
    // HANDLE hFile = CreateFileW(L" C:\\Windows\\System32\\Chakra.dll", // File path (wide character)
    //     GENERIC_READ,                     // Desired access
    //     FILE_SHARE_READ,                  // Sharing mode
    //     NULL,                             // Security attributes
    //     OPEN_EXISTING,                    // Creation disposition
    //     FILE_ATTRIBUTE_NORMAL,            // Flags and attributes
    //     NULL                              // Template file
    // );
    HMODULE chak = LoadLibraryExW(L"C:\\Windows\\System32\\Chakra.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if(!chak){
        printf("no chak %lu\n", GetLastError());
    }
    PVOID chakrabase = GetModuleBase(L"Chakra.dll");
    if (!chakrabase) {
    printf("no chakrabase %lu\n", GetLastError());
    }
    printf("address of chakrabase: %p\n", chakrabase);

    if (!VirtualProtect(chakrabase, sp, PAGE_EXECUTE_READWRITE, &old)) {
    printf("no VirtualProtect %lu\n", GetLastError());
    }

    memcpy(chakrabase, pay, sizeof(pay));
    printf("enter to change permission\n");
    getchar();

    if (!VirtualProtect(chakrabase, sp, PAGE_EXECUTE_READ, &old)) {
    printf("no VirtualProtect %lu\n", GetLastError());
    }
    printf("check permision of: %p\n", chakrabase);
    getchar();
    return 0;
}
