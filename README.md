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
