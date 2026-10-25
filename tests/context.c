#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>

typedef NTSTATUS (WINAPI *continue_fn)(CONTEXT *, BOOLEAN);
static unsigned checks, failures;
static volatile LONG phase;
extern void trigger_breakpoint(void);
extern void trigger_access_violation(void);

static __attribute__((noinline)) uintptr_t stack_pointer(void)
{
    uintptr_t value;
    __asm__ volatile("movq %%rsp,%0" : "=r"(value));
    return value;
}

static void check(int value, const char *label)
{
    ++checks;
    if(!value) ++failures;
    printf("%s %s\n",value ? "PASS" : "FAIL",label);
}

static int filter(EXCEPTION_POINTERS *p, const char *name)
{
    printf("CONTEXT %s code=%08lx flags=%08lx ctxflags=%08lx rsp_mod16=%llu rip_minus_address=%lld\n",
           name,p->ExceptionRecord->ExceptionCode,p->ExceptionRecord->ExceptionFlags,
           p->ContextRecord->ContextFlags,(unsigned long long)(p->ContextRecord->Rsp & 15),
           (long long)(p->ContextRecord->Rip-(uintptr_t)p->ExceptionRecord->ExceptionAddress));
    return EXCEPTION_EXECUTE_HANDLER;
}

static __attribute__((noinline)) void test_breakpoint(void)
{
    uintptr_t before=stack_pointer(), after;
    int caught=0;
    __try {
        trigger_breakpoint();
    } __except(filter(GetExceptionInformation(),"int3")) {
        caught=1;
        printf("HANDLER int3 rsp_mod16=%llu\n",(unsigned long long)(stack_pointer()&15));
    }
    after=stack_pointer();
    check(caught,"int3 handler entered");
    check(before==after,"int3 unwind preserves stack");
}

static __attribute__((noinline)) void test_nested(void)
{
    uintptr_t before=stack_pointer();
    volatile LONG finally_count=0, caught=0;
    __try {
        __try {
            trigger_access_violation();
        } __finally {
            ++finally_count;
            printf("FINALLY rsp_mod16=%llu abnormal=%d\n",
                   (unsigned long long)(stack_pointer()&15),AbnormalTermination());
        }
    } __except(filter(GetExceptionInformation(),"access-violation")) {
        caught=1;
    }
    check(caught && finally_count==1,"nested unwind executes finally once");
    check(before==stack_pointer(),"nested unwind preserves stack");
}

static __attribute__((noinline)) void test_restore(void)
{
    CONTEXT context;
    uintptr_t before=stack_pointer();
    phase=0;
    RtlCaptureContext(&context);
    if(InterlockedCompareExchange(&phase,1,0)==0) {
        printf("CAPTURE restore rsp_mod16=%llu flags=%08lx\n",
               (unsigned long long)(context.Rsp&15),context.ContextFlags);
        RtlRestoreContext(&context,NULL);
        check(0,"RtlRestoreContext must transfer control");
    }
    check(phase==1,"RtlRestoreContext resumes captured point");
    check(before==stack_pointer(),"RtlRestoreContext preserves stack");
}

static __attribute__((noinline)) void test_continue(void)
{
    CONTEXT context;
    continue_fn cont=(continue_fn)(void *)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtContinue");
    uintptr_t before=stack_pointer();
    phase=0;
    RtlCaptureContext(&context);
    if(InterlockedCompareExchange(&phase,1,0)==0) {
        printf("CAPTURE continue rsp_mod16=%llu flags=%08lx\n",
               (unsigned long long)(context.Rsp&15),context.ContextFlags);
        cont(&context,FALSE);
        check(0,"NtContinue must transfer control");
    }
    check(phase==1,"NtContinue resumes captured point");
    check(before==stack_pointer(),"NtContinue preserves stack");
}

int main(void)
{
    setvbuf(stdout,NULL,_IONBF,0);
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    test_breakpoint();
    test_nested();
    test_restore();
    test_continue();
    printf("RESULT: %u checks, %u failures\n",checks,failures);
    return failures ? 1 : 0;
}
