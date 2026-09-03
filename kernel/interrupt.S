.global idt_load_asm
.type idt_load_asm, @function

idt_load_asm:
    lidt (%rdi)
    ret

.size idt_load_asm, .-idt_load_asm


# ===============================================================
# Common exception entry
#
# On entry, CPU has already pushed:
#
#   RIP
#   CS
#   RFLAGS
#   [RSP]
#   [SS]
#
# For exceptions with an error code, CPU additionally pushed:
#
#   ERROR_CODE
#
# The individual ISR stubs normalize the stack to:
#
#   VECTOR
#   ERROR_CODE
#   RIP
#   CS
#   RFLAGS
#   [RSP]
#   [SS]
#
# Then this common stub saves all GPRs.
# ===============================================================

.type isr_common_stub, @function
isr_common_stub:

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

    call exception_dispatcher

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax

    addq $16, %rsp
    iretq

.size isr_common_stub, .-isr_common_stub


# ===============================================================
# Exception without CPU error code
#
# Push:
#   dummy error_code = 0
#   vector
# ===============================================================

.macro ISR_NOERR num
.global isr\num
.type isr\num, @function

isr\num:
    cli
    pushq $0
    pushq $\num
    jmp isr_common_stub

.size isr\num, .-isr\num
.endm


# ===============================================================
# Exception with CPU error code
#
# CPU has already pushed error_code.
#
# Push only:
#   vector
# ===============================================================

.macro ISR_ERR num
.global isr\num
.type isr\num, @function

isr\num:
    cli
    pushq $\num
    jmp isr_common_stub

.size isr\num, .-isr\num
.endm


# ===============================================================
# Exception vectors currently implemented
# ===============================================================

# #DE — Divide Error — CPU does NOT push error code
ISR_NOERR 0

# #GP — General Protection — CPU DOES push error code
ISR_ERR 13
# #DB — Debug — no error code
ISR_NOERR 1
# NMI — Non-Maskable Interrupt — no error code
ISR_NOERR 2
# #BP — Breakpoint — no error code
ISR_NOERR 3
# #OF — Overflow — no error code
ISR_NOERR 4
# #BR — Bound Range Exceeded — no error code
ISR_NOERR 5
# #UD — Invalid Opcode — no error code
ISR_NOERR 6
# #NM — Device Not Available — no error code
ISR_NOERR 7
# #DF — Double Fault — CPU DOES push error code
ISR_ERR 8
# Vector 9 — legacy, unused on modern CPUs, no error code
ISR_NOERR 9
# #TS — Invalid TSS — CPU DOES push error code
ISR_ERR 10
# #NP — Segment Not Present — CPU DOES push error code
ISR_ERR 11
# #SS — Stack-Segment Fault — CPU DOES push error code
ISR_ERR 12
# #PF — Page Fault — CPU DOES push error code
ISR_ERR 14
# #MF — x87 Floating-Point Error — no error code
ISR_NOERR 16
# #AC — Alignment Check — CPU DOES push error code
ISR_ERR 17
# #MC — Machine Check — no error code
ISR_NOERR 18
# #XM — SIMD Floating-Point Exception — no error code
ISR_NOERR 19

# ===============================================================
# IRQ common entry (BEDA dari exception!)
#
# IRQ tidak pernah punya error code dari CPU. Handler-nya TIDAK
# boleh halt permanen seperti exception_dispatcher -- timer harus
# terus berdetak. irq_number dipush manual supaya handler C tahu
# IRQ mana yang terpicu (perlu untuk kirim EOI ke PIC yang benar).
# ===============================================================
.type irq_common_stub, @function
irq_common_stub:
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
    call irq_handler
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    addq $16, %rsp
    iretq
.size irq_common_stub, .-irq_common_stub

.macro IRQ num, irq_num
.global irq\num
.type irq\num, @function
irq\num:
    cli
    pushq $0
    pushq $\irq_num
    jmp irq_common_stub
.size irq\num, .-irq\num
.endm

# IRQ0 = timer, terhubung ke vektor 32 setelah PIC remap
IRQ 32, 0
