// R6-3: pengganti minimal <limine.h> untuk uji host pmm.c (hanya struktur
// memmap yang dipakai pmm_init). Kernel memakai header asli di tools/limine.
#ifndef BMAHOS_HOST_LIMINE_H
#define BMAHOS_HOST_LIMINE_H

#include <stdint.h>

#define LIMINE_MEMMAP_USABLE   0
#define LIMINE_MEMMAP_RESERVED 1

struct limine_memmap_entry {
    uint64_t base;
    uint64_t length;
    uint64_t type;
};

struct limine_memmap_response {
    uint64_t revision;
    uint64_t entry_count;
    struct limine_memmap_entry **entries;
};

#endif
