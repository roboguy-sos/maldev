EXTERN wNtAllocateVirtualMemory:DWORD               ; Extern keyword indicates that the symbol is defined in another module. Here it's the syscall number for NtAllocateVirtualMemory.
EXTERN sysAddrNtAllocateVirtualMemory:QWORD         ; The actual address of the NtAllocateVirtualMemory syscall in ntdll.dll.


.code
NtAllocateVirtualMemory PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10. This is necessary because the syscall instruction in 64-bit Windows expects the parameters to be in the r10 and rdx registers.
    mov eax, wNtAllocateVirtualMemory               ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtAllocateVirtualMemory]  ; Jump to the actual syscall.
NtAllocateVirtualMemory ENDP                        ; End of the procedure.

end