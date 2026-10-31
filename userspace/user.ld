/* P5-1: program user = biner datar di 0x400000 (USER_VADDR_ALLOC_BASE, sched.c).
   Halaman kode user read-only: .data/.bss tidak boleh ada. */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

SECTIONS
{
    . = 0x400000;
    .text : {
        *(.text.start)
        *(.text .text.*)
        *(.rodata .rodata.*)
    }
    .data : { *(.data .data.*) }
    .bss : { *(.bss .bss.* COMMON) }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
ASSERT(SIZEOF(.data) + SIZEOF(.bss) == 0, "program user tidak boleh punya .data/.bss")
ASSERT(SIZEOF(.text) <= 4096, "program user maks 4096 byte")
