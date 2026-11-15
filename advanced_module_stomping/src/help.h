#pragma once
#include <windows.h>
#include <libloaderapi.h>
#include <winnt.h>
#include <winternl.h>
// ============================================================
// PEB / loader walking
// ============================================================
inline PPEB GetPeb() {
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

typedef struct pro_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;           // +0x000
    LIST_ENTRY InMemoryOrderLinks;         // +0x010
    LIST_ENTRY InInitializationOrderLinks; // +0x020
    PVOID      DllBase;                    // +0x030
    PVOID      EntryPoint;                 // +0x038
    ULONG      SizeOfImage;               // +0x040
    UNICODE_STRING FullDllName;            // +0x048
    UNICODE_STRING BaseDllName;            // +0x058
    union {
        ULONG Flags;                       // +0x068
        struct {
            ULONG PackagedBinary          : 1;
            ULONG MarkedForRemoval        : 1;
            ULONG ImageDll                : 1;
            ULONG LoadNotificationsSent   : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport     : 1;
            ULONG InLegacyLists           : 1;
            ULONG InIndexes               : 1;
            ULONG ShimDll                 : 1;
            ULONG InExceptionTable        : 1;
            ULONG ReservedFlags1          : 2;
            ULONG LoadInProgress          : 1;
            ULONG LoadConfigProcessed     : 1;
            ULONG EntryProcessed          : 1;
            ULONG ProtectDelayLoad        : 1;
            ULONG ReservedFlags3          : 2;
            ULONG DontCallForThreads      : 1;
            ULONG ProcessAttachCalled     : 1;
            ULONG ProcessAttachFailed     : 1;
            ULONG CorImage                : 1;
            ULONG DontRelocate            : 1;
            ULONG CorILOnly               : 1;
            ULONG ChpeImage               : 1;
            ULONG ChpeEmulatorImage       : 1;
            ULONG ReservedFlags5          : 1;
            ULONG Redirected              : 1;
            ULONG ReservedFlags6          : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
} pro_LDR_DATA_TABLE_ENTRY, *pro_PLDR_DATA_TABLE_ENTRY;
PVOID find_gadget_ret(void) {
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)hNt + ((PIMAGE_DOS_HEADER)hNt)->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp(".text", (char *)sec[i].Name) == 0) {
            PBYTE base = (PBYTE)((ULONG_PTR)hNt + sec[i].VirtualAddress);
            DWORD size = sec[i].Misc.VirtualSize;
            for (DWORD j = 0; j < size; j++) {
                if (base[j] == 0xC3)
                    return (PVOID)(base + j);
            }
        }
    }
    return NULL;
}


PVOID GetModuleBase(const wchar_t* modulename) {
	PPEB pPeb = GetPeb();
	if (!pPeb || !pPeb->Ldr)
		return NULL;

	PPEB_LDR_DATA pLdr = pPeb->Ldr;
	PLIST_ENTRY   head = &pLdr->InMemoryOrderModuleList;
	PLIST_ENTRY   curr = head->Flink;

	while (curr != head) {
		PMY_LDR_DATA_TABLE_ENTRY entry =
			CONTAINING_RECORD(curr, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (entry->BaseDllName.Buffer && _wcsicmp(entry->BaseDllName.Buffer, modulename) == 0){
		entry->EntryPoint = find_gadget_ret();
        entry->Flags |= 0x00000004;   // LDRP_IMAGE_DLL
        entry->Flags |= 0x00000008;   // LDRP_LOAD_NOTIFICATIONS_SENT
        entry->Flags |= 0x00000020;   // LDRP_PROCESS_STATIC_IMPORT
        entry->Flags |= 0x00004000;   // LDRP_ENTRY_PROCESSED
        entry->Flags |= 0x00040000;   // LDRP_DONT_CALL_FOR_THREADS
        return entry->DllBase;
		}

		curr = curr->Flink;
	}
	return NULL;
}
