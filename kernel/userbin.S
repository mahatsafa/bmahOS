// P5-1: program user yang ditanam di kernel (build/user/*.bin, dari userspace/).
    .section .rodata
    .global user_udpgema_start
    .global user_udpgema_end
user_udpgema_start:
    .incbin "build/user/udpgema.bin"
user_udpgema_end:
    .global user_tcpgema_start
    .global user_tcpgema_end
user_tcpgema_start:
    .incbin "build/user/tcpgema.bin"   // P5-2
user_tcpgema_end:
    .global user_tcpklien_start
    .global user_tcpklien_end
user_tcpklien_start:
    .incbin "build/user/tcpklien.bin"   // P5-3
user_tcpklien_end:
    .section .note.GNU-stack,"",@progbits
