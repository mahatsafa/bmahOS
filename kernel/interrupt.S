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

1:
    hlt
    jmp 1b

.size isr0, .-isr0
