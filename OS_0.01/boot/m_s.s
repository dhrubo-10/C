; Boot I/O & Runtime Support for the kernel

; for lyli... while checking..
;i wrote it  in x86_64 bare-metal and compiled with NASM + LD on Linux. so if you try to build,run it on macOS 
; or Windows, you may need to adjust:
; NASM/LD toolchain commands, Linking flags, emulator setup, and reg pos.
; best way- run first compile and run in x86 linux.

global _start
global putc, putw, flush, getc, getw

section .bss
outbuf:    resb 512            ; output buffer
obufp:     resq 1              ; pointer into buffer
ibuf:      resb 512            ; input buffer
ibufc:     resq 1              ; count of chars left
ibufp:     resq 1              ; input buffer pointer

section .data
fout:      dq 1                ; file descriptor for stdout
fin:       dq 0                ; file descriptor for stdin

section .text

putc:
    push rax
    push rdi
    mov rax, [obufp]
    mov byte [outbuf + rax], dil
    inc rax
    mov [obufp], rax
    cmp rax, 512
    jl .done
    ; flush if full
    call flush
    xor rax, rax
    mov [obufp], rax
.done:
    pop rdi
    pop rax
    ret

; putw: write a word (16-bit) as two chars

putw:
    mov ax, di
    mov dl, al         ; low byte
    mov rdi, rdx
    call putc
    mov dl, ah         ; high byte
    mov rdi, rdx
    call putc
    ret

; flush: flush output buffer to stdout

flush:
    push rax
    push rdi
    push rsi
    push rdx
    mov rax, 1          ; sys_write
    mov rdi, [fout]     ; fd
    lea rsi, [outbuf]
    mov rdx, [obufp]    ; how many chars
    syscall
    xor rax, rax
    mov [obufp], rax    ; reset buffer pointer
    pop rdx
    pop rsi
    pop rdi
    pop rax
    ret


; getc: get a char from buffer, refill if empty
; returns char in al, sign-extended in rax
getc:
    cmp qword [ibufc], 0
    jg .haschar
    ; refill buffer
    mov rax, 0          ; sys_read
    mov rdi, [fin]
    lea rsi, [ibuf]
    mov rdx, 512
    syscall
    test rax, rax
    jle .eof
    mov [ibufc], rax
    mov qword [ibufp], ibuf
.haschar:
    dec qword [ibufc]
    mov rsi, [ibufp]
    mov al, [rsi]
    inc rsi
    mov [ibufp], rsi
    movzx rax, al
    ret
.eof:
    mov rax, -1
    ret


getw:
    call getc
    cmp rax, -1
    je .eof
    mov bl, al
    call getc
    cmp rax, -1
    je .eof
    shl rax, 8
    or rax, rbx
    movzx eax, ax
    ret
.eof:
    mov rax, -1
    ret

_start:
    mov rdi, 'H'
    call putc
    mov rdi, 'i'
    call putc
    call flush

    mov rax, 60         ; exit
    xor rdi, rdi
    syscall
; doneeee