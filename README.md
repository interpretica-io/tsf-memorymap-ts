# tsf-memorymap-ts

A Test Environment suite that exercises
[tsf-memorymap](https://github.com/interpretica-io/tsf-memorymap)
(`tapi_memmap`) against the agent it runs on.

| Test | What it checks |
|---|---|
| `elf` | a riscv64 image parsed (class/endian/machine/entry/segments/sections), the flash-to-RAM image's `vaddr`≠`paddr` split, a file read back from the agent, a non-ELF refused with `EBADF` |
| `ram` | free RAM computed to the byte over a region, by `vaddr` and by `paddr`, and an over-large image reported as overflowing |
| `audit` | a RWX segment reported through tsf-cybersec, a clean image raising nothing |
| `proc` | the RPC server's own map read live (stack, executable code, resident size from smaps), the W^X audit run, a missing pid → `ENOENT` |

The riscv64 ELF fixtures are built into the `elf`/`ram`/`audit` tests as byte
arrays (`memmap/fixtures.inc`), so the arch-agnostic parser is exercised on a
target the agent could never run.

## Running it

Needs Docker and `test-environment` as a sibling directory:

```bash
./scripts/run.sh docker guess --cfg=localhost
```

`conf/external.yml` names the `tsf-*` repositories; point a `url` at a local
checkout while developing. The `elf`/`ram`/`audit` tests need no agent for the
parse itself; `proc` and the file-read path use a real Test Agent with
`ta_rpcprovider`.

Verified green on Debian 12.
