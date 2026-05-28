/** @file
 * @brief Memory-map Group
 *
 * Parsing an ELF of another architecture (riscv64) from bytes, and
 * reading one back from a file on the agent.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "memmap/elf"

#include "te_config.h"
#include <inttypes.h>
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_file.h"
#include "rcf_api.h"

#include "tapi_memmap.h"
#include "tapi_memmap_elf.h"
#include "tsapi_cybersec.h"

#include "fixtures.inc"

#define T_MS 30000

/** The single LOAD segment of the flat riscv64 image. */
static const tapi_memmap_seg *
first_load(const tapi_memmap_image *image)
{
    const tapi_memmap_seg *seg;

    TAPI_MEMMAP_FOREACH_LOAD(image, seg)
        return seg;
    return NULL;
}

int
main(int argc, char **argv)
{
    tsapi_cybersec_session sess;
    tapi_memmap_image image;
    const tapi_memmap_seg *seg;
    const tapi_memmap_sec *bss;

    TEST_START;

    TEST_STEP("Open a session to the agent");
    CHECK_RC(tsapi_cybersec_session_init(&sess, "pco_memmap_elf"));

    TEST_STEP("Parse a riscv64 image from its bytes");
    CHECK_RC(tapi_memmap_elf_parse(fw_elf, sizeof(fw_elf), &image));
    tapi_memmap_image_log(&image);

    TEST_SUBSTEP("It is read as riscv64, ELF64, little-endian");
    if (image.machine != 243)
        TEST_VERDICT("machine is %u (%s), expected RISC-V(243)",
                     image.machine, tapi_memmap_machine2str(image.machine));
    if (!image.is64 || image.big_endian)
        TEST_VERDICT("class/endianness read wrong");
    if (image.entry != 0x80000000ULL)
        TEST_VERDICT("entry is 0x%" PRIx64 ", expected 0x80000000",
                     image.entry);

    TEST_SUBSTEP("Its one LOAD segment is what the linker made");
    seg = first_load(&image);
    if (seg == NULL)
        TEST_VERDICT("no LOAD segment");
    if (seg->vaddr != 0x7ffff000ULL || seg->paddr != 0x7ffff000ULL)
        TEST_VERDICT("LOAD addr v=0x%" PRIx64 " p=0x%" PRIx64,
                     seg->vaddr, seg->paddr);
    if (seg->memsz != 0x211e0ULL || seg->filesz != 0x11e0ULL)
        TEST_VERDICT("LOAD sizes filesz=0x%" PRIx64 " memsz=0x%" PRIx64,
                     seg->filesz, seg->memsz);
    /* The .bss is the memsz beyond the filesz: 128 KiB. */
    if (seg->memsz - seg->filesz != 0x20000ULL)
        TEST_VERDICT("bss is %" PRIu64 ", expected 131072",
                     seg->memsz - seg->filesz);
    if (!((seg->perms & TAPI_MEMMAP_R) && (seg->perms & TAPI_MEMMAP_W) &&
          (seg->perms & TAPI_MEMMAP_X)))
        TEST_VERDICT("the RWX segment did not read as rwx");

    TEST_SUBSTEP("Its .bss section is found by name");
    bss = tapi_memmap_section(&image, ".bss");
    if (bss == NULL)
        TEST_VERDICT("no .bss section");
    RING(".bss addr 0x%" PRIx64 " size %" PRIu64, bss->addr, bss->size);
    tapi_memmap_image_free(&image);

    TEST_STEP("The flash-to-RAM image keeps vaddr and paddr apart");
    CHECK_RC(tapi_memmap_elf_parse(fw2_elf, sizeof(fw2_elf), &image));
    tapi_memmap_image_log(&image);
    {
        bool saw_split = false;

        TAPI_MEMMAP_FOREACH_LOAD(&image, seg)
        {
            if (seg->vaddr == 0x80000000ULL && seg->paddr == 0x20010000ULL)
                saw_split = true;
        }
        if (!saw_split)
            TEST_VERDICT("the .data segment's vaddr(RAM)/paddr(flash) "
                         "split was not read");
    }
    tapi_memmap_image_free(&image);

    TEST_STEP("Read an image from a file on the agent");
    {
        const char *ta = TSAPI_CYBERSEC_TA;
        te_string path = TE_STRING_INIT;
        te_string local = TE_STRING_INIT;
        FILE *fp;

        /* Lay the fixture down on the engine, push it to the agent. */
        tapi_file_make_custom_pathname(&local, getenv("TE_TMP"), ".elf");
        fp = fopen(local.ptr, "wb");
        if (fp == NULL)
            TEST_FAIL("cannot write %s", local.ptr);
        fwrite(fw_elf, 1, sizeof(fw_elf), fp);
        fclose(fp);
        tapi_file_make_custom_pathname(&path, "/tmp", ".elf");
        CHECK_RC(rcf_ta_put_file(ta, 0, local.ptr, path.ptr));

        CHECK_RC(tapi_memmap_elf_read(sess.factory, path.ptr, T_MS, &image));
        if (image.machine != 243 || image.entry != 0x80000000ULL)
            TEST_VERDICT("the file read back wrong");
        tapi_memmap_image_free(&image);

        tapi_file_ta_unlink_fmt(ta, "%s", path.ptr);
        unlink(local.ptr);
        te_string_free(&path);
        te_string_free(&local);
    }

    TEST_STEP("A non-ELF file is refused, not mis-parsed");
    {
        te_string bad = TE_STRING_INIT;
        te_errno rc;

        tapi_file_make_custom_pathname(&bad, "/tmp", ".txt");
        CHECK_RC(tapi_file_create_ta(TSAPI_CYBERSEC_TA, bad.ptr,
                                     "not an elf\n"));
        rc = tapi_memmap_elf_read(sess.factory, bad.ptr, T_MS, &image);
        if (TE_RC_GET_ERROR(rc) != TE_EBADF)
            TEST_VERDICT("a text file gave %r, not EBADF", rc);
        tapi_file_ta_unlink_fmt(TSAPI_CYBERSEC_TA, "%s", bad.ptr);
        te_string_free(&bad);
    }

    TEST_SUCCESS;

cleanup:
    tsapi_cybersec_session_fini(&sess);
    TEST_END;
}
