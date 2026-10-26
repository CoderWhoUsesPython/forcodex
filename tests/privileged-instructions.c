/* Original user-mode instruction exception probe. No application code. */
#include <windows.h>
#ifdef _MSC_VER
#include <intrin.h>
#define __cpuid_count(leaf,sub,a,b,c,d) do { int regs[4]; __cpuidex(regs,leaf,sub); a=regs[0]; b=regs[1]; c=regs[2]; d=regs[3]; } while(0)
#else
#include <cpuid.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned char *active, *resume;
static volatile DWORD observed;
static LONG CALLBACK handler(EXCEPTION_POINTERS *p)
{
    if ((uintptr_t)p->ContextRecord->Rip != (uintptr_t)active)
        return EXCEPTION_CONTINUE_SEARCH;
    observed = p->ExceptionRecord->ExceptionCode;
    printf("EXCEPTION code=%08lx parameters=%lu address_matches=%d",
           observed, p->ExceptionRecord->NumberParameters,
           p->ExceptionRecord->ExceptionAddress == active);
    for (DWORD i = 0; i < p->ExceptionRecord->NumberParameters; ++i)
        printf(" info%lu=%llx", i,
               (unsigned long long)p->ExceptionRecord->ExceptionInformation[i]);
    puts("");
    p->ContextRecord->Rip = (uintptr_t)resume;
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main(void)
{
    static const struct {
        const char *name;
        unsigned char bytes[3];
        unsigned length;
        DWORD expected; /* Zero records a platform-dependent observation. */
    } tests[] = {
        {"vmcall",  {0x0f, 0x01, 0xc1}, 3, 0},
        {"vmmcall", {0x0f, 0x01, 0xd9}, 3, 0},
        {"cli",     {0xfa},             1, EXCEPTION_PRIV_INSTRUCTION},
        {"ud2",     {0x0f, 0x0b},       2, EXCEPTION_ILLEGAL_INSTRUCTION},
    };
    unsigned a, b, c, d, failures = 0;
    char vendor[13] = {0}, hypervisor[13] = {0};
    void *veh;
    unsigned char *code = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT,
                                      PAGE_EXECUTE_READWRITE);
    setvbuf(stdout, NULL, _IONBF, 0);
    __cpuid_count(0, 0, a, b, c, d);
    memcpy(vendor, &b, 4); memcpy(vendor + 4, &d, 4); memcpy(vendor + 8, &c, 4);
    __cpuid_count(1, 0, a, b, c, d);
    printf("CPU vendor=%s family_model=%08x hypervisor=%u vmx=%u\n",
           vendor, a, c >> 31, (c >> 5) & 1);
    if (c >> 31) {
        __cpuid_count(0x40000000, 0, a, b, c, d);
        memcpy(hypervisor, &b, 4); memcpy(hypervisor + 4, &c, 4); memcpy(hypervisor + 8, &d, 4);
        printf("HYPERVISOR vendor=%s max_leaf=%08x\n", hypervisor, a);
    }
    veh = AddVectoredExceptionHandler(1, handler);
    if (!code || !veh) return 2;
    for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        /* Clear volatile inputs, then execute exactly one tested instruction. */
        static const unsigned char zero[] = {0x31,0xc0,0x31,0xc9,0x31,0xd2};
        memcpy(code, zero, sizeof(zero));
        active = code + sizeof(zero);
        memcpy(active, tests[i].bytes, tests[i].length);
        resume = active + tests[i].length;
        *resume = 0xc3;
        FlushInstructionCache(GetCurrentProcess(), code, 4096);
        observed = 0;
        printf("INSTRUCTION name=%s\n", tests[i].name);
        ((void (*)(void))(uintptr_t)code)();
        printf("OBSERVED name=%s exception=%08lx\n", tests[i].name, observed);
        if (tests[i].expected && observed != tests[i].expected) ++failures;
    }
    RemoveVectoredExceptionHandler(veh);
    VirtualFree(code, 0, MEM_RELEASE);
    printf("RESULT: 4 observations, %u control failures\n", failures);
    return failures ? 1 : 0;
}
