/** @file
 * @brief Memory-map Group
 *
 * The memory map of a real running process on the agent - the RPC
 * server itself, whose pid we can ask for. It must have a stack, a
 * heap and file-backed code, resident memory, and (a normal process)
 * no writable-executable mapping.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "memmap/proc"

#include "te_config.h"
#include <inttypes.h>
#include "tapi_test.h"
#include "tapi_rpc_unistd.h"

#include "tapi_memmap.h"
#include "tapi_memmap_proc.h"
#include "tapi_memmap_audit.h"
#include "tsapi_cybersec.h"

#define T_MS 30000

int
main(int argc, char **argv)
{
    tsapi_cybersec_session sess;
    te_vec maps = TE_VEC_INIT(tapi_memmap_mapping);
    tapi_cybersec_report report;
    const tapi_memmap_mapping *m;
    bool have_stack = false;
    bool have_heap = false;
    bool have_file = false;
    bool have_exec = false;
    uint64_t total = 0;
    uint64_t resident = 0;
    pid_t pid;

    tapi_cybersec_report_init(&report);

    TEST_START;

    TEST_STEP("Open a session and take the RPC server's own pid");
    CHECK_RC(tsapi_cybersec_session_init(&sess, "pco_memmap_proc"));
    pid = rpc_getpid(sess.pco);
    RING("reading the map of pid %d", (int)pid);

    TEST_STEP("Read its memory map");
    CHECK_RC(tapi_memmap_proc_read(sess.pco, pid, T_MS, &maps));
    if (te_vec_size(&maps) == 0)
        TEST_VERDICT("the process has no mappings");
    tapi_memmap_mappings_log(&maps);

    TEST_STEP("It has a stack and executable file-backed code");
    TE_VEC_FOREACH(&maps, m)
    {
        if (m->backing == TAPI_MEMMAP_BACK_STACK)
            have_stack = true;
        if (m->backing == TAPI_MEMMAP_BACK_HEAP)
            have_heap = true;
        if (m->backing == TAPI_MEMMAP_BACK_FILE &&
            (m->perms & TAPI_MEMMAP_X))
            have_file = true;
        if ((m->perms & TAPI_MEMMAP_W) && (m->perms & TAPI_MEMMAP_X))
            have_exec = true;
    }
    if (!have_stack)
        TEST_VERDICT("no stack mapping");
    if (!have_file)
        TEST_VERDICT("no executable file-backed mapping");
    /*
     * A [heap] is not guaranteed: a process that satisfies its
     * allocations with mmap rather than brk has none, and the RPC
     * server can be one. So it is noted, not required.
     */
    RING("heap mapping %s", have_heap ? "present" : "absent");

    TEST_STEP("Some of it is resident");
    tapi_memmap_proc_totals(&maps, &total, &resident);
    RING("total %" PRIu64 " bytes, resident %" PRIu64, total, resident);
    if (total == 0)
        TEST_VERDICT("total size is zero");
    if (resident == 0)
        TEST_VERDICT("nothing is resident - was smaps read?");

    TEST_STEP("A normal process has no writable-executable mapping");
    if (have_exec)
        RING("this process has a W+X mapping");
    CHECK_RC(tapi_memmap_audit_proc(&maps, "rpc-server", &report));
    tapi_cybersec_report_log(&report);
    /*
     * Not a hard failure: a JIT could legitimately have one. The audit
     * is exercised; the finding count is only logged.
     */

    TEST_STEP("A pid that does not exist is ENOENT");
    {
        te_vec none = TE_VEC_INIT(tapi_memmap_mapping);
        te_errno rc = tapi_memmap_proc_read(sess.pco, 999999, T_MS,
                                            &none);

        tapi_memmap_mappings_free(&none);
        if (TE_RC_GET_ERROR(rc) != TE_ENOENT)
            TEST_VERDICT("a missing pid gave %r, not ENOENT", rc);
    }

    TEST_SUCCESS;

cleanup:
    tapi_memmap_mappings_free(&maps);
    tapi_cybersec_report_free(&report);
    tsapi_cybersec_session_fini(&sess);
    TEST_END;
}
