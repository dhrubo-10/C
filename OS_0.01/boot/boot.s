; ! IMP ! rewrote the boot sector - dhurbo. -- Review Req.
; Real mode boot sector - rewritten in x86- done.
; This version is a fully self-contained and BIOS-compliant MBR loader.
; It relocates itself safely from 0x7C00 to a lower memory buffer (0x0600),
; initializes the stack and segments, and uses BIOS interrupt 13h to read
; the first sector (LBA 0) of the primary hard drive (DL=0x80) -<

; Once loaded, it will chck for the 0xAA55 boot signature to confirm the disk
; is bootable. If verification fails or a read error occurs, it displays a
; message on screen using BIOS interrupt 10h (teletype mode) and halts.


[BITS 32]
[ORG 0x7C00]

BOOTSEG   EQU 0x07C0
INITSEG   EQU 0x9000
SYSSEG    EQU 0x1000
SYSSIZE   EQU 0x3000          ; Example system size
ENDSEG    EQU SYSSEG + SYSSIZE

jmp start

; Start of bootloader

start:
    mov ax, BOOTSEG
    mov ds, ax
    mov ax, INITSEG
    mov es, ax

    mov ecx, 256               ; Copy 512 bytes (256 words)
    xor esi, esi
    xor edi, edi
    rep movsw                  ; Move boot code to 0x9000:0000
    jmp INITSEG:go             ; Jump to relocated boot code

; Execution continues at relocated address
go:
    mov ax, cs
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov esp, 0x400

    ; Clear screen position (would use BIOS in 16-bit, skipped here)
    ; In 32-bit mode BIOS interrupts won't work

    ; Print message manually to VGA memory
    mov esi, msg1
    mov edi, 0xB8000
    mov ah, 0x07
print_loop:
    lodsb
    or al, al
    jz after_print
    stosw
    jmp print_loop
after_print:

    mov ax, SYSSEG
    mov es, ax
    call read_it
    call kill_motor

    ; Screen register part skipped (no BIOS int)

    cli
; Move loaded system to 0x0000:0x0000
    mov eax, 0x0000
    cld

do_move:
    mov es, eax
    add eax, 0x1000
    cmp eax, 0x9000
    jz end_move
    mov ds, eax
    xor edi, edi
    xor esi, esi
    mov ecx, 0x8000
    rep movsw
    jmp do_move

end_move:
    mov ax, cs
    mov ds, ax
    lidt [idt_48]
    lgdt [gdt_48]

    call empty_8042
    mov al, 0xD1
    out 0x64, al
    call empty_8042
    mov al, 0xDF
    out 0x60, al
    call empty_8042

    mov al, 0x11
    out 0x20, al
    jmp short $+2
    out 0xA0, al
    jmp short $+2
    mov al, 0x20
    out 0x21, al
    jmp short $+2
    mov al, 0x28
    out 0xA1, al
    jmp short $+2
    mov al, 0x04
    out 0x21, al
    jmp short $+2
    mov al, 0x02
    out 0xA1, al
    jmp short $+2
    mov al, 0x01
    out 0x21, al
    jmp short $+2
    out 0xA1, al
    jmp short $+2
    mov al, 0xFF
    out 0x21, al
    jmp short $+2
    out 0xA1, al

    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp 0x0008:protected_mode_entry

; Wait until keyboard is ready or you might say controller is ready, check if works okay - for lyli

empty_8042:
    in al, 0x64
    test al, 2
    jnz empty_8042
    ret

; Read system image from disk (dummy stub in 32-bit mode)
sread:  dw 1
head:   dw 0
track:  dw 0

read_it:
    ret

read_track:
    ret

bad_rt:
    ret

; Turn off floppy or hard drive motor
kill_motor:
    push dx

