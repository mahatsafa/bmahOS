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
