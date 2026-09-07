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

.global enter_usermode
.type enter_usermode, @function

# void enter_usermode(uint64_t entry_vaddr, uint64_t user_stack_top)
# rdi = entry_vaddr (RIP tujuan di ring 3)
# rsi = user_stack_top (RSP awal task user, sudah nunjuk ke alamat
#       tertinggi stack karena stack tumbuh ke bawah)
#
# Selector: user data = GDT index 6 * 8 = 0x30, | RPL 3 = 0x33
#           user code = GDT index 5 * 8 = 0x28, | RPL 3 = 0x2B
enter_usermode:
    movw $0x33, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    pushq $0x33
    pushq %rsi
    pushq $0x202
    pushq $0x2B
    pushq %rdi

    iretq

.size enter_usermode, .-enter_usermode
