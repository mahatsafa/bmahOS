.global idt_load_asm
.type idt_load_asm, @function

idt_load_asm:
    lidt (%rdi)
    ret

.size idt_load_asm, .-idt_load_asm


.global isr0
.type isr0, @function

isr0:
    cli

    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    movq %rsp, %rdi
    subq $8, %rsp
    call exception_handler

1:
    hlt
    jmp 1b

.size isr0, .-isr0
