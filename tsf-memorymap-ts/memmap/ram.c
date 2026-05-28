/** @file
 * @brief Memory-map Group
 *
 * Free-RAM computation over a region, by vaddr and by paddr, checked
 * against numbers known from how the fixtures were linked.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "memmap/ram"

#include "te_config.h"
#include <inttypes.h>
#include "tapi_test.h"

#include "tapi_memmap.h"
#include "tapi_memmap_elf.h"
#include "tapi_memmap_ram.h"
#include "tsapi_cybersec.h"

#include "fixtures.inc"

int
main(int argc, char **argv)
{
    tapi_memmap_image image;
    /*
     * The image's one segment is placed at 0x7ffff000 (a page below its
     * 0x80000000 entry, where the ELF headers go), so the RAM region is
     * taken from there: 512 KiB of RAM that the image loads into.
     */
    tapi_memmap_region ram = { .base = 0x7ffff000ULL, .size = 512 * 1024,
                               .name = "RAM" };
    tapi_memmap_usage usage;
    uint64_t free_start = 0;
    uint64_t free_size = 0;

    TEST_START;

    TEST_STEP("Parse the flat riscv64 image");
    CHECK_RC(tapi_memmap_elf_parse(fw_elf, sizeof(fw_elf), &image));

    TEST_STEP("Its segment occupies the low end of RAM, the rest is free");
    /*
     * The segment runs 0x7ffff000..0x800201e0, memsz 0x211e0 = 135648
     * bytes, all inside the region, so 512 KiB - 135648 = 388640 free.
     */
    CHECK_RC(tapi_memmap_ram_usage(&image, &ram, 1, TAPI_MEMMAP_BY_VADDR,
                                   &usage));
    tapi_memmap_usage_log(&usage);
    if (usage.total != 512 * 1024)
        TEST_VERDICT("total is %" PRIu64, usage.total);
    if (usage.used != 135648)
        TEST_VERDICT("used is %" PRIu64 ", expected 135648", usage.used);
    if (usage.free != 388640)
        TEST_VERDICT("free is %" PRIu64 ", expected 388640", usage.free);
    if (!usage.fits)
        TEST_VERDICT("a segment that fits was reported as overflowing");
    if (usage.overlap)
        TEST_VERDICT("a single segment was reported as overlapping");

    TEST_STEP("The largest free span is the tail of RAM");
    if (!tapi_memmap_ram_largest_free(&usage, &free_start, &free_size))
        TEST_VERDICT("no free span found");
    if (free_start != 0x800201e0ULL || free_size != 388640)
        TEST_VERDICT("largest free is 0x%" PRIx64 "+%" PRIu64,
                     free_start, free_size);
    tapi_memmap_usage_free(&usage);
    tapi_memmap_image_free(&image);

    TEST_STEP("The flash-to-RAM image: by paddr nothing is in RAM");
    CHECK_RC(tapi_memmap_elf_parse(fw2_elf, sizeof(fw2_elf), &image));
    /*
     * Both segments load from flash (paddr 0x2xxxxxxx), so against a
     * RAM region at 0x80000000 the by-paddr occupancy is zero.
     */
    CHECK_RC(tapi_memmap_ram_usage(&image, &ram, 1, TAPI_MEMMAP_BY_PADDR,
                                   &usage));
    tapi_memmap_usage_log(&usage);
    if (usage.used != 0 || usage.free != 512 * 1024)
        TEST_VERDICT("by paddr, RAM used=%" PRIu64 " free=%" PRIu64,
                     usage.used, usage.free);
    tapi_memmap_usage_free(&usage);

    TEST_STEP("By vaddr, its .data+.bss do sit in RAM");
    /* .data runs at vaddr 0x80000000, memsz 0x20008 = 131080 bytes. */
    CHECK_RC(tapi_memmap_ram_usage(&image, &ram, 1, TAPI_MEMMAP_BY_VADDR,
                                   &usage));
    tapi_memmap_usage_log(&usage);
    if (usage.used != 0x20008)
        TEST_VERDICT("by vaddr, RAM used=%" PRIu64 ", expected 131080",
                     usage.used);
    tapi_memmap_usage_free(&usage);

    TEST_STEP("An image too big for RAM is reported as overflowing");
    {
        tapi_memmap_region tiny = { .base = 0x80000000ULL, .size = 64 * 1024,
                                    .name = "tiny" };

        CHECK_RC(tapi_memmap_ram_usage(&image, &tiny, 1,
                                       TAPI_MEMMAP_BY_VADDR, &usage));
        if (usage.fits)
            TEST_VERDICT("a 128 KiB image fit in 64 KiB");
        if (usage.overflow == 0)
            TEST_VERDICT("overflow not reported");
        RING("overflow %" PRIu64 " bytes", usage.overflow);
        tapi_memmap_usage_free(&usage);
    }
    tapi_memmap_image_free(&image);

    TEST_SUCCESS;

cleanup:
    TEST_END;
}
