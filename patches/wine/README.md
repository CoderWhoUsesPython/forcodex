# Wine kernel-pool accounting experiments

These patches apply in numeric order to the local Wine Staging 11.20 source
baseline (Wine 7298a818b79446bae153b8d5aa27235ab3703bf9, Staging
711f5be0b016c2730c268eb92369bf56b9ec9782). They implement system-information
classes 22 and 66 using Wine's own ExAllocatePool allocations, rather than
inventing Windows drivers or host-kernel pool tags. Generated protocol files
are included; run tools/make_requests after changing protocol.def again.

The complete local Roblox experiment also has earlier compatibility patches;
these two patches alone are not a complete Roblox launch solution.

Allocation records are owned by the allocating Wine process. Queries aggregate
real paged/nonpaged counts and outstanding bytes across the Wine server.
Large blocks are page-backed and aligned; executable/NX types are preserved.
Free, process exit, and explicit ntoskrnl module unload release the records.
Historical per-tag allocation/free counts remain available within that server.
Small-block accounting reports requested bytes; large-block accounting reports
committed page bytes. This does not model every Windows pool allocator's
metadata overhead, restricted-token policy, or Linux kernel allocations.
WoW64 query-layout conversion remains unsupported; both 32-bit and 64-bit pool
allocation clients are accounted and visible to a 64-bit query client.

Validation:

- Windows reference: https://github.com/CoderWhoUsesPython/forcodex/actions/runs/40206727685
- Identical Windows-built pool query probes pass four assertions each under
  patched Wine. Minimum lengths and NULL-buffer behavior match the reference;
  counts and contents reflect each system's actual allocations.
- Native Wine regression probes pass 115 API assertions, 16 context assertions
  and seven CPU/debug assertions.
- tests/wine-pool-accounting.c passes 37 integration checks with a 64-bit child,
  and another 37 with a 32-bit child. It checks sizes, tags, paging type,
  concurrency, cross-process visibility, free, process exit and module unload.
  This integration test is Wine-local; it is not run on Windows Actions.

Incremental targets for the configured x86-64/WoW64 build:

```sh
make -j14 dlls/ntdll/ntdll.so server/wineserver \
  dlls/ntoskrnl.exe/x86_64-windows/ntoskrnl.exe \
  dlls/ntoskrnl.exe/i386-windows/ntoskrnl.exe
```

Restart the dedicated test prefix's wineserver after rebuilding: the protocol
changes require matching client/server binaries. Allocation accounting adds
server round trips and is not performance-optimized. Windows reference probes
contain no Roblox code, and Roblox is never run in the workflow.
