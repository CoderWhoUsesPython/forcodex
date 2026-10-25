/* Original CPU/Windows exception probes; no application code. */
#include <windows.h>
#include <winternl.h>
#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>

typedef NTSTATUS (WINAPI *context_fn)(HANDLE, CONTEXT *);
static volatile LONG illegal, steps, hits;
static unsigned checks, failures;
static void check(int ok, const char *name)
{
    ++checks; if (!ok) ++failures;
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
}
static LONG CALLBACK handler(EXCEPTION_POINTERS *p)
{
    if (p->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        unsigned char *pc=(unsigned char *)(uintptr_t)p->ContextRecord->Rip;
        if (pc[0]==0x0f && pc[1]==0x01 && (pc[2]==0xee || pc[2]==0xef)) {
            ++illegal;
            printf("PKRU_EXCEPTION opcode=%02x code=%08lx\n",pc[2],p->ExceptionRecord->ExceptionCode);
            p->ContextRecord->Rip+=3;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    if (p->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        printf("DEBUG_EXCEPTION dr6=%llx dr7=%llx flags=%lx\n",
            (unsigned long long)p->ContextRecord->Dr6,
            (unsigned long long)p->ContextRecord->Dr7,p->ContextRecord->EFlags);
        if (p->ContextRecord->Dr6 & 1) {
            ++hits;
            p->ContextRecord->Dr7=0;
            p->ContextRecord->EFlags|=0x10000;
        } else ++steps;
        p->ContextRecord->EFlags&=~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static __attribute__((noinline)) void target(void)
{
    __asm__ volatile("nop" ::: "memory");
}
extern void test_trap_flag(void);
__asm__(".text\n.globl test_trap_flag\n"
        "test_trap_flag:\n pushfq\n orq $0x100,(%rsp)\n popfq\n nop\n ret\n");
int main(void)
{
    unsigned a=0,b=0,c=0,d=0,lo=0,hi=0;
    LONG before;
    CONTEXT old={0},ctx={0};
    HMODULE ntdll=GetModuleHandleA("ntdll.dll");
    context_fn get=(context_fn)(void *)GetProcAddress(ntdll,"NtGetContextThread");
    context_fn set=(context_fn)(void *)GetProcAddress(ntdll,"NtSetContextThread");
    void *veh=AddVectoredExceptionHandler(1,handler);
    __cpuid_count(7,0,a,b,c,d);
    printf("CPUID7 eax=%08x ebx=%08x ecx=%08x edx=%08x PKU=%u OSPKE=%u\n",a,b,c,d,(c>>3)&1,(c>>4)&1);
    before=illegal;
    __asm__ volatile("rdpkru" : "=a"(lo),"=d"(hi) : "c"(0));
    printf("RDPKRU success=%d eax=%08x edx=%08x\n",illegal==before,lo,hi);
    check((illegal==before)==!!(c&16),"RDPKRU agrees with OS enablement");
    if (illegal==before) {
        __asm__ volatile("wrpkru" :: "a"(lo),"d"(0),"c"(0) : "memory");
        check(illegal==before,"WRPKRU restores unchanged value");
    }
    test_trap_flag();
    check(steps==1,"trap flag delivers one exception");
    old.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    NTSTATUS status=get((HANDLE)(LONG_PTR)-2,&old);
    printf("GET_DEBUG status=%08lx\n",status);
    check(status==0,"get current debug registers");
    if (!status) {
        ctx.ContextFlags=CONTEXT_DEBUG_REGISTERS;
        ctx.Dr0=(uintptr_t)target;
        ctx.Dr7=1;
        status=set((HANDLE)(LONG_PTR)-2,&ctx);
        printf("SET_DEBUG status=%08lx\n",status);
        check(status==0,"set current execution breakpoint");
        if (!status) { target(); check(hits==1,"execution breakpoint fires once"); }
        status=set((HANDLE)(LONG_PTR)-2,&old);
        check(status==0,"restore original debug registers");
    }
    RemoveVectoredExceptionHandler(veh);
    printf("RESULT: %u checks, %u failures\n",checks,failures);
    return failures ? 1 : 0;
}
