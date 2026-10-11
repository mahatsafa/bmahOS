#include <limine.h>
#include "kernel.h"

static uint8_t pmm_bitmap[PMM_BITMAP_SIZE];

uint64_t pmm_usable_memory = 0;
static uint64_t pmm_usable_frames = 0;
static uint64_t pmm_next_frame = 0;

static void pmm_bitmap_set(uint64_t frame)
{
    pmm_bitmap[frame / 8] |= (uint8_t)(1U << (frame % 8));
}

static void pmm_bitmap_clear(uint64_t frame)
{
    pmm_bitmap[frame / 8] &= (uint8_t)~(1U << (frame % 8));
}

int pmm_bitmap_test(uint64_t frame)
{
    return (pmm_bitmap[frame / 8] &
            (uint8_t)(1U << (frame % 8))) != 0;
}

static uint64_t pmm_align_up(uint64_t value)
{
    return (value + PMM_PAGE_SIZE - 1) &
           ~(PMM_PAGE_SIZE - 1);
}

static uint64_t pmm_align_down(uint64_t value)
{
    return value & ~(PMM_PAGE_SIZE - 1);
}

void pmm_init(struct limine_memmap_response *response)
{
    for (uint64_t i = 0; i < PMM_BITMAP_SIZE; i++) {
        pmm_bitmap[i] = 0xFF;
    }

    pmm_usable_memory = 0;
    pmm_usable_frames = 0;
    pmm_next_frame = 0;

    for (uint64_t i = 0; i < response->entry_count; i++) {
        struct limine_memmap_entry *entry = response->entries[i];

        if (entry->type != LIMINE_MEMMAP_USABLE) {
            continue;
        }

        uint64_t start = pmm_align_up(entry->base);
        uint64_t end = pmm_align_down(entry->base + entry->length);

        if (end <= start) {
            continue;
        }

        if (start >= PMM_MAX_PHYS_ADDR) {
            continue;
        }

        if (end > PMM_MAX_PHYS_ADDR) {
            end = PMM_MAX_PHYS_ADDR;
        }

        uint64_t length = end - start;
        uint64_t first_frame = start / PMM_PAGE_SIZE;
        uint64_t last_frame = end / PMM_PAGE_SIZE;

        pmm_usable_memory += length;
        pmm_usable_frames += last_frame - first_frame;

        for (uint64_t frame = first_frame;
             frame < last_frame;
             frame++) {
            pmm_bitmap_clear(frame);
        }
    }

    /* Frame 0 tidak pernah dibagikan: alamat fisik 0 = tanda gagal
       untuk pmm_alloc() dan diabaikan pmm_free(). */
    if (!pmm_bitmap_test(0)) {
        pmm_bitmap_set(0);
        pmm_usable_memory -= PMM_PAGE_SIZE;
        pmm_usable_frames -= 1;
    }
}

uint64_t pmm_alloc(void)
{
    for (uint64_t frame = pmm_next_frame;
         frame < PMM_MAX_FRAMES;
         frame++) {

        if (!pmm_bitmap_test(frame)) {
            pmm_bitmap_set(frame);
            pmm_next_frame = frame + 1;

            return frame * PMM_PAGE_SIZE;
        }
    }

    return 0;
}

void pmm_free(uint64_t phys_addr)
{
    if (phys_addr == 0) {
        return;
    }

    if ((phys_addr & (PMM_PAGE_SIZE - 1)) != 0) {
        return;
    }

    uint64_t frame = phys_addr / PMM_PAGE_SIZE;

    if (frame >= PMM_MAX_FRAMES) {
        return;
    }

    if (pmm_bitmap_test(frame)) {
        pmm_bitmap_clear(frame);

        if (frame < pmm_next_frame) {
            pmm_next_frame = frame;
        }
    }
}
