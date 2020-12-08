        BITS 64
        global _start
        section .text

_start:
        lea     eax, [rel end+0x4]
next:
        inc     eax
        cmp     dword [eax-0x4], 'SLAE'
        jne     next
        jmp     rax
end:

