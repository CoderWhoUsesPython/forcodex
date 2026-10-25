# Windows / Wine compatibility probes

Standalone Windows API and CPU/exception behavior tests for comparison with a
local Wine build. The workflow does not download, install, or run Roblox, and
contains no Roblox executables or extracted client code.

The Windows API reference workflow builds the probes on Windows Server 2022
and uploads their executables, logs, status CSV, and machine/compiler metadata.
Run the same uploaded executables under Wine to compare identical machine code.

`accuracy.c` exercises API argument validation, resource lookup, SSE alignment
fixups, and records process/thread information-query statuses. Some assertions
began as local compatibility hypotheses; failures on Windows are evidence to
correct those hypotheses. `context.c` records exception context, stack
alignment, structured unwind, and context restoration at two optimization levels.

Results are version-specific. Passing these probes does not establish complete
compatibility with any application or constitute a complete protection test suite.

## Recorded baseline

[Windows reference run 40160126040](https://github.com/CoderWhoUsesPython/forcodex/actions/runs/40160126040)
used commit `c70ab7af38c57a9e785b7a4f9ef0107fc6d02d47` on Windows Server
2022 Datacenter, x64, build 20348. All 115 accuracy assertions and all eight
context assertions at each optimization level passed. The API sweep records
1,936 process/thread query combinations; these rows are observations, not
assertions that every Windows version must behave identically.

The identical uploaded binaries also passed those assertions under the local
modified Wine Staging 11.20 build. Both context logs matched Windows exactly.
This does not establish that Roblox launches; its local startup still fails.

Compare downloaded reference artifacts with a local Wine result directory:

```sh
python3 scripts/compare.py --windows /path/to/windows-reference \
  --wine /path/to/wine-results --output comparison.json
```

Both directories must contain `accuracy-statuses.csv`; matching context logs
are compared when available. Status and return-length differences require
review for OS-version, environment, and unimplemented-feature differences.
The tool reports differences without treating all of them as Wine defects.

## CPU and debug-register observations

`cpu-state.c` is a separate original probe for CPUID PKU/OSPKE exposure, both
PKRU instructions, trap-flag delivery and an execution breakpoint set on the
current thread. [Run 40161556948](https://github.com/CoderWhoUsesPython/forcodex/actions/runs/40161556948)
passes all seven checks on Windows. The VM exposes PKU=0 and OSPKE=0, and both
instructions raise STATUS_ILLEGAL_INSTRUCTION. The identical executable passes
all seven checks on the local Intel Linux/Wine host, which instead exposes
PKU=1 and OSPKE=1 and executes both instructions. The differing host CPUs mean
this comparison does not establish Windows CPU exposure on that Intel laptop.
