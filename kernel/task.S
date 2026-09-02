.global context_switch
.type context_switch, @function

# void context_switch(uint64_t *old_rsp_ptr, uint64_t new_rsp)
# rdi = old_rsp_ptr  (tempat menyimpan rsp task lama)
# rsi = new_rsp      (rsp task baru yang mau dipakai)
context_switch:
    # Simpan callee-saved register (System V AMD64 ABI) ke stack
    # task LAMA -- ini yang membuat "snapshot" state task lama.
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    # Simpan rsp sekarang (sudah termasuk register yang baru di-push)
    # ke *old_rsp_ptr, supaya task lama bisa di-resume nanti.
    movq %rsp, (%rdi)

    # Pindah ke stack task BARU.
    movq %rsi, %rsp

    # Pop kembali register, tapi sekarang dari stack task BARU --
    # otomatis jadi nilai register milik task baru.
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx

    # ret akan pop "return address" dari stack task baru -- ini
    # yang membuat CPU "melompat" ke entry point task baru (kalau
    # baru pertama kali dijalankan) atau titik terakhir task itu
    # berhenti (kalau sudah pernah jalan sebelumnya).
    ret

.size context_switch, .-context_switch
