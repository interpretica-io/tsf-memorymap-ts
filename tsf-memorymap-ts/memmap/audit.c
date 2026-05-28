/** @file
 * @brief Memory-map Group
 *
 * The W^X audit of a binary image. The flat fixture has a single RWX
 * LOAD segment on purpose, so the assertion is that the audit reports
 * it; the flash-to-RAM fixture is clean (r-x and rw-), so it must not.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "memmap/audit"

#include "te_config.h"
#include "tapi_test.h"

#include "tapi_memmap.h"
#include "tapi_memmap_elf.h"
#include "tapi_memmap_audit.h"
#include "tsapi_cybersec.h"

#include "fixtures.inc"

int
main(int argc, char **argv)
{
    tapi_memmap_image image;
    tapi_cybersec_report report;

    tapi_cybersec_report_init(&report);

    TEST_START;

    TEST_STEP("A RWX segment is reported");
    CHECK_RC(tapi_memmap_elf_parse(fw_elf, sizeof(fw_elf), &image));
    CHECK_RC(tapi_memmap_audit_image(&image, "riscv64-fw.elf", &report));
    tapi_cybersec_report_log(&report);
    TSAPI_CYBERSEC_EXPECT(&report, "memmap.wx-segment");
    tapi_memmap_image_free(&image);
    tapi_cybersec_report_free(&report);

    TEST_STEP("A clean image raises no W^X finding");
    tapi_cybersec_report_init(&report);
    CHECK_RC(tapi_memmap_elf_parse(fw2_elf, sizeof(fw2_elf), &image));
    CHECK_RC(tapi_memmap_audit_image(&image, "riscv64-fw2.elf", &report));
    tapi_cybersec_report_log(&report);
    if (tsapi_cybersec_report_has(&report, "memmap.wx-segment"))
        TEST_VERDICT("a clean image was reported as W+X");
    tapi_memmap_image_free(&image);

    TEST_SUCCESS;

cleanup:
    tapi_cybersec_report_free(&report);
    TEST_END;
}
