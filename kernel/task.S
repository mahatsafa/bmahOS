.global context_switch
.type context_switch, @function
# void context_switch(uint64_t *old_rsp_ptr, uint64_t new_rsp, uint64_t new_pml4_phys)
# rdi = old_rsp_ptr, rsi = new_rsp, rdx = new_pml4_phys
context_switch:
    # Simpan SEMUA register (15) milik task lama, urutan sama
    # persis dengan irq_common_stub supaya kompatibel dipanggil
    # dari dalam interrupt context nanti (Tahap 3).
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
    # Simpan rsp task lama.
    movq %rsp, (%rdi)
    # Layer 8 checkpoint 2: ganti CR3 HANYA kalau PML4 tujuan beda
    # dari CR3 sekarang -- reload CR3 flush SELURUH TLB, mahal kalau
    # dilakukan sia-sia untuk switch antar task yang share PML4 sama
    # (mis. Task A <-> Task B, keduanya pakai PML4 kernel global).
    movq %cr3, %rax
    cmpq %rdx, %rax
    je   .Lskip_cr3_switch
    movq %rdx, %cr3
.Lskip_cr3_switch:
    # Pindah ke stack task baru.
    movq %rsi, %rsp
    # Pulihkan 15 register milik task baru, urutan kebalikan push.
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
    # ret melompat ke entry_function (task baru) atau titik
    # terakhir task ini berhenti (kalau sudah pernah jalan).
    ret
.size context_switch, .-context_switch
