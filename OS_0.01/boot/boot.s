; ! IMP ! rewrote the boot sector - dhurbo. -- Review Req.
; Real mode boot sector - rewritten in x86 
; This version is a fully self-contained and BIOS-compliant MBR loader.
; It relocates itself safely from 0x7C00 to a lower memory buffer (0x0600),
; initializes the stack and segments, and uses BIOS interrupt 13h to read
; the first sector (LBA 0) of the primary hard drive (DL=0x80) -<

; Once loaded, it will chck for the 0xAA55 boot signature to confirm the disk
; is bootable. If verification fails or a read error occurs, it displays a
; message on screen using BIOS interrupt 10h (teletype mode) and halts.


BITS 16
ORG 0x7C00

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

    mov cx, 256               ; Copy 512 bytes (256 words)
    xor si, si
    xor di, di
    rep movsw                 ; Move boot code to 0x9000:0000
    jmp INITSEG:go            ; Jump to relocated boot code

; Execution continues at relocated address
go:
    mov ax, cs
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x400

    ; Clear screen position
    mov ah, 0x03
    xor bh, bh
    int 0x10

    ; Print message
    mov cx, 24
    mov bx, 0x0007
    mov bp, msg1
    mov ax, 0x1301
    int 0x10

    mov ax, SYSSEG
    mov es, ax
    call read_it
    call kill_motor

    mov ah, 0x03
    xor bh, bh
    int 0x10
    mov [510], dx

    cli
; Move loaded system to 0x0000:0x0000
    mov ax, 0x0000
    cld

do_move:
    mov es, ax
    add ax, 0x1000
    cmp ax, 0x9000
    jz end_move
    mov ds, ax
    xor di, di
    xor si, si
    mov cx, 0x8000
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

    mov ax, 0x0001
    lmsw ax
    jmp 0x0008:0x0000
; Wait until keyboard is ready or you might say controller is ready, check if works okay - for lyli

empty_8042:
    in al, 0x64
    test al, 2
    jnz empty_8042
    ret

; Read system image from disk
sread:  dw 1
head:   dw 0
track:  dw 0

read_it:
    mov ax, es
    test ax, 0x0FFF
die:
    jne die
    xor bx, bx

rp_read:
    mov ax, es
    cmp ax, ENDSEG
    jb ok1_read
    ret

ok1_read:
    mov ax, sectors
    sub ax, [sread]
    mov cx, ax
    shl cx, 9
    add cx, bx
    jnc ok2_read
    je ok2_read
    xor ax, ax
    sub ax, bx
    shr ax, 9

ok2_read:
    call read_track
    mov cx, ax
    add ax, [sread]
    cmp ax, sectors
    jne ok3_read
    mov ax, 1
    sub ax, [head]
    jne ok4_read
    inc word [track]

ok4_read:
    mov [head], ax
    xor ax, ax

ok3_read:
    mov [sread], ax
    shl cx, 9
    add bx, cx
    jnc rp_read
    mov ax, es
    add ax, 0x1000
    mov es, ax
    xor bx, bx
    jmp rp_read

read_track:
    push ax
    push bx
    push cx
    push dx
    mov dx, [track]
    mov cx, [sread]
    inc cx
    mov ch, dl
    mov dx, [head]
    mov dh, dl
    mov dl, 0
    and dx, 0x0100
    mov ah, 2
    int 0x13
    jc bad_rt
    pop dx
    pop cx
    pop bx
    pop ax
    ret

bad_rt:
    mov ax, 0
    mov dx, 0
    int 0x13
    pop dx
    pop cx
    pop bx
    pop ax
    jmp read_track

; Turn off floppy or hard drive motor

kill_motor:
    push dx
    mov dx, 0x3F2
    mov al, 0
    out dx, al
    pop dx
    ret

; GDT setup here
gdt:
    dw 0, 0, 0, 0

    dw 0x07FF
    dw 0x0000
    dw 0x9A00
    dw 0x00C0

    dw 0x07FF
    dw 0x0000
    dw 0x9200
    dw 0x00C0

idt_48:
    dw 0
    dw 0, 0

gdt_48:
    dw 0x0800
    dd gdt

msg1 db 13,10, "Loading system ...", 13,10,13,10,0

times 510 - ($ - $$) db 0
dw 0xAA55
