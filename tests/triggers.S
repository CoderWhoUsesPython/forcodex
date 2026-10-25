/* Tiny leaf functions keep faulting instructions inside an external call's
 * SEH scope, even with compilers that do not model asynchronous C exceptions.
 */
.text
.globl trigger_breakpoint
.def trigger_breakpoint; .scl 2; .type 32; .endef
.seh_proc trigger_breakpoint
trigger_breakpoint:
.seh_endprologue
int3
ret
.seh_endproc

.globl trigger_access_violation
.def trigger_access_violation; .scl 2; .type 32; .endef
.seh_proc trigger_access_violation
trigger_access_violation:
.seh_endprologue
xor %eax,%eax
movl $1,(%rax)
ret
.seh_endproc
