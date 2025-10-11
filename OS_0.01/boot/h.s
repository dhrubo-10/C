; all credit to Sayem Sadik.


section .text
global format_disk

format_disk:
    push msg_ready
    call print_string
    add esp, 4

    call read_char

    cmp al, 'y'
    jne .exit

    mov ecx, 203*2
    xor ebx, ebx

.format_loop:
    mov edi, buf
    mov [edi], ebx
    add ebx, 0x20
    dec ecx
    jnz .format_loop

    jmp .exit

.error:
    push msg_error
    call print_string
    add esp, 4
    jmp .exit

.exit:
    ret

print_string:
    push ebp
    mov ebp, esp
    mov esi, [ebp+8]
.print_loop:
    lodsb
    test al, al
    jz .done
    jmp .print_loop
.done:
    pop ebp
    ret

read_char:
    mov al, 'y'
    ret

section .data
msg_ready db "Ready drive 0 and type y", 10, 0
msg_error db "fct: error", 10, 0
buf       times 512 db 0
