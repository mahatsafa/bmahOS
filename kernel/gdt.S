.global gdt_load_and_reload_asm
.type gdt_load_and_reload_asm, @function

gdt_load_and_reload_asm:
    pushq %rbp
    movq %rsp, %rbp

    lgdt (%rdi)

    pushq $0x08
    leaq 1f(%rip), %rax
    pushq %rax
    lretq

1:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss

    popq %rbp
    ret

.size gdt_load_and_reload_asm, .-gdt_load_and_reload_asm

.global tss_load_asm
.type tss_load_asm, @function

tss_load_asm:
    movw $0x18, %ax
    ltr %ax
    ret

.global tss_read_asm
.type tss_read_asm, @function

tss_read_asm:
    xorq %rax, %rax
    str %ax
    ret

.size tss_load_asm, .-tss_load_asm
.size tss_read_asm, .-tss_read_asm
