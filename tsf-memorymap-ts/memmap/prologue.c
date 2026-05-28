/** @file
 * @brief Memory-map Group
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */
#define TE_TEST_NAME    "memmap/prologue"
#include "te_config.h"
#include "tapi_test.h"
#include "tsapi_evo.h"
int
main(int argc, char **argv)
{
    TEST_START;
    TEST_STEP("memmap group prologue");
    TEST_SUCCESS;
cleanup:
    TEST_END;
}
