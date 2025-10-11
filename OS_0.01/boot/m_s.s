; Boot I/O & Runtime Support for the kernel

global _start
global putc, putw, flush, getc, getw

section .bss
outbuf:    resb 512            ; output buffer
obufp:     resd 1              ; pointer into buffer
ibuf:      resb 512            ; input buffer
ibufc:     resd 1              ; count of chars left
ibufp:     resd 1              ; input buffer pointer

section .data
fout:      dd 1                ; file descriptor for stdout
fin:       dd 0                ; file descriptor for stdin

section .text

putc:
    push eax
    push edi
    mov eax, [obufp]
    mov [outbuf + eax], dil  
    inc eax
    mov [obufp], eax
    cmp eax, 512
    jl .done
    ; flush if full
    call flush
    xor eax, eax
    mov [obufp], eax
.done:
    pop edi
    pop eax
    ret

; putw: write a word (16-bit) as two chars

putw:
    mov ax, di
    mov dl, al         ; low byte
    movzx edi, dl
    call putc
    mov dl, ah         ; high byte
    movzx edi, dl
    call putc
    ret

; flush: flush output buffer to stdout

flush:
    push eax
    push ebx
    push ecx
    push edx
    mov eax, 4          ; sys_write
    mov ebx, [fout]     ; fd
    lea ecx, [outbuf]
    mov edx, [obufp]    ; how many chars
    int 0x80
    xor eax, eax
    mov [obufp], eax    ; reset buffer pointer
    pop edx
    pop ecx
    pop ebx
    pop eax
    ret



getc:
    cmp dword [ibufc], 0
    jg .haschar
    ; refill buffer
    mov eax, 3          ; sys_read
    mov ebx, [fin]
    lea ecx, [ibuf]
    mov edx, 512
    int 0x80
    test eax, eax
    jle .eof
    mov [ibufc], eax
    mov dword [ibufp], ibuf
.haschar:
    dec dword [ibufc]
    mov esi, [ibufp]
    mov al, [esi]
    inc esi
    mov [ibufp], esi
    movzx eax, al
    ret
.eof:
    mov eax, -1
    ret


getw:
    call getc
    cmp eax, -1
    je .eof
    mov bl, al
    call getc
    cmp eax, -1
    je .eof
    shl eax, 8
    or eax, ebx
    movzx eax, ax
    ret
.eof:
    mov eax, -1
    ret

_start:
    mov edi, 'H'
    call putc
    mov edi, 'i'
    call putc
    call flush

    mov eax, 1          ; sys_exit
    xor ebx, ebx
    int 0x80
; doneeee
