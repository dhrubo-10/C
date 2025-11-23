
[BITS 32]
[ORG 0x7C00]

section .text
global _start

_start:
 
    mov esi, msg_ready
    call print_string


    call get_key
    cmp al, 'y'
    jne exit

    ; Initialize format loop
    mov ecx, 203 * 2        ; r4 in PDP-11 version
    xor ebx, ebx            ; r3 = 0 (sector offset)

fmt_loop:
    mov eax, ebx            ; current sector (simulating rkda)
    push eax
    push buffer             ; simulated buffer pointer
    push dword -12 * 256    ; simulated byte count
    push dword 6003         ; simulated command word

    ; Simulate I/O wait
wait_io:
    
    nop
    dec dword [wait_count]
    jnz wait_io

   
    mov eax, [wait_count]
    test eax, eax
    js fmt_error

    add ebx, 20             ; next sector
    dec ecx
    jnz fmt_loop
    jmp exit

fmt_error:
    mov esi, msg_error
    call print_string
    jmp exit


print_string:
    mov edi, 0xB8000
    mov ah, 0x07
.pr_loop:
    lodsb
    or al, al
    jz .done
    stosw
    jmp .pr_loop
.done:
    ret


get_key:
    mov al, 'y'
    ret


exit:
    hlt
    jmp exit

section .data

msg_ready db "Ready drive 0 and type y", 13, 10, 0
msg_error db "fct: error", 13, 10, 0
wait_count dd 100000
buffer     times 512 db 0

times 510 - ($ - $$) db 0
dw 0xAA55
