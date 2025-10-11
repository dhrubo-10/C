; a basic I/O abstraction for a kernel or runtime, couldve wrote it in C, 
; but whatever. asm version seems more fun - SD.

[bits 32]

section .data
    msg_cannot_open db "Cannot open wtmp", 10, 0
    filnam         db "/usr/adm/wtmp", 0
    total_str      db "total   ", 0
    blank          db 9, 0               ; tab
    monasc         db "JanFebMarAprMayJunJulAugSepOctNovDec", 0
    day            dd 45436.0, 32000.0, 0.0, 0.0
    thous          dd 47600.0, 137374.0, 0.0, 0.0
    maxpd          dd 45636.0, 32001.0, 0.0, 0.0
    sixth          dd 40031.0, 114631.0, 114631.0, 114631.0
    ten            dd 41040.0, 0.0, 0.0, 0.0
    montab         dd 31,28,31,30,31,30,31,31,30,31,30,31
                    dd 31,29,31,30,31,30,31,31,30,31,30,31

section .bss
    midnight  resq 1
    byday     resw 1
    argc      resw 1
    argp      resw 1
    ibuf      resb 16
    fbuf      resb 520
    ttyf      resb (20*18)
    usrf      resb (200*16)
    obuf      resb 20
    pflg      resw 1

section .text
global _start



_start:
    mov     eax, [esp]            ; argc
    mov     [argc], ax

    lea     ebx, [esp+4]          ; argv pointer
    mov     [argp], bx

    
    mov     eax, 5                ; sys_open
    mov     ebx, filnam
    xor     ecx, ecx              
    int     0x80
    test    eax, eax
    js      cannot_open
    mov     [fbuf], eax           ; store file descriptor

read_loop:
   
    mov     eax, 3                ; sys_read
    mov     ebx, [fbuf]
    mov     ecx, ibuf
    mov     edx, 16
    int     0x80
    test    eax, eax
    jle     time_exit             
    call    loop
    jmp     read_loop

cannot_open:
    
    mov     eax, 4
    mov     ebx, 1
    mov     ecx, msg_cannot_open
    mov     edx, 20
    int     0x80
    jmp     time_exit



loop:
    ; this placeholder simulates the record-processing loop
    ; original used floating-point ops (movf, cmpf, etc.)
    finit
    fld     qword [midnight]      ; load midnight value
    ; (further date/time calculations omitted)
    ret



print:
    mov     eax, 4
    mov     ebx, 1
    mov     ecx, total_str
    mov     edx, 8
    int     0x80
    ret



time_exit:
    mov     eax, 1
    xor     ebx, ebx
    int     0x80
