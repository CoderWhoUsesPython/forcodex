/* Focused regression tests for the observed Windows compatibility checks.
 * Also writes status-code sweeps for comparison on a reference Windows host.
 * This is not a copy or a complete implementation of Hyperion's test suite.
 */
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef NTSTATUS (WINAPI *set_thread_fn)(HANDLE, ULONG, void *, ULONG);
typedef NTSTATUS (WINAPI *query_fn)(HANDLE, ULONG, void *, ULONG, ULONG *);
typedef NTSTATUS (WINAPI *resource_fn)(HMODULE, ULONG_PTR *, ULONG, ULONG,
                                      void **, SIZE_T *, WCHAR *, ULONG *);
static set_thread_fn set_thread;
static query_fn query_thread, query_process;
static unsigned failures, checks, exceptions;
static BYTE *active_code;
static unsigned active_length;

static void check(int pass, const char *label)
{
    ++checks;
    if (!pass) ++failures;
    printf("%s %s\n", pass ? "PASS" : "FAIL", label);
}

static LONG CALLBACK handler(EXCEPTION_POINTERS *ep)
{
    if ((ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
         ep->ExceptionRecord->ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT) &&
        ep->ContextRecord->Rip == (DWORD64)(uintptr_t)active_code)
    {
        ++exceptions;
        ep->ContextRecord->Rip += active_length;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

struct move_case
{
    const char *name;
    BYTE code[8];
    unsigned length, patch;
    BYTE replacement;
    unsigned offset;
};

static const struct move_case moves[] = {
    {"movdqa store", {0x66,0x0f,0x7f,0x01}, 4,0,0xf3,1},
    {"movdqa load", {0x66,0x0f,0x6f,0x01}, 4,0,0xf3,1},
    {"movaps store", {0x0f,0x29,0x01}, 3,1,0x11,1},
    {"movaps load", {0x0f,0x28,0x01}, 3,1,0x10,1},
    {"movapd store", {0x66,0x0f,0x29,0x01}, 4,2,0x11,1},
    {"movapd load", {0x66,0x0f,0x28,0x01}, 4,2,0x10,1},
    {"movdqa extended register", {0x66,0x44,0x0f,0x7f,0x09}, 5,0,0xf3,1},
    {"movdqa SIB+disp8", {0x66,0x0f,0x7f,0x44,0x11,0x01}, 6,0,0xf3,0},
};

static void test_move(const struct move_case *m, int set_enabled, int expected_enabled)
{
    BYTE *scratch = VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    BYTE *code = VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    BOOLEAN enabled = set_enabled > 0;
    BYTE result;
    DWORD old;
    int32_t displacement = (int32_t)m->patch - (int32_t)(m->length + 7);
    MEMORY_BASIC_INFORMATION mbi;
    char label[160];
    unsigned before;
    if (!scratch || !code) { check(0,"allocate test memory"); ExitProcess(1); }
    if (set_enabled >= 0)
        check(set_thread(GetCurrentThread(),7,&enabled,1)==0,"set alignment state");
    memcpy(code,m->code,m->length);
    code[m->length]=0x80; code[m->length+1]=0x3d;
    memcpy(code+m->length+2,&displacement,4);
    code[m->length+6]=m->replacement;
    code[m->length+7]=0x0f; code[m->length+8]=0x95; code[m->length+9]=0xc0;
    code[m->length+10]=0xc3;
    check(VirtualProtect(code,4096,PAGE_EXECUTE_READ,&old),"protect test RX");
    FlushInstructionCache(GetCurrentProcess(),code,4096);
    active_code=code; active_length=m->length; before=exceptions;
    result=((BYTE (*)(void *,ULONG_PTR))code)(scratch+m->offset,0);
    active_code=NULL;
    snprintf(label,sizeof(label),"%s enabled=%d: exception delivery",m->name,expected_enabled);
    check(exceptions-before==(expected_enabled ? 0u : 1u),label);
    snprintf(label,sizeof(label),"%s enabled=%d: observable instruction rewrite",m->name,expected_enabled);
    check(result==(expected_enabled ? 0 : 1),label);
    VirtualQuery(code,&mbi,sizeof(mbi));
    check(mbi.Protect==PAGE_EXECUTE_READ,"code protection preserved");
    VirtualFree(code,0,MEM_RELEASE); VirtualFree(scratch,0,MEM_RELEASE);
}

static DWORD WINAPI worker(void *arg)
{
    (void)arg;
    test_move(&moves[0],-1,0);
    return 0;
}

static void test_statuses(void)
{
    BOOLEAN enable=TRUE;
    ULONG returned=0;
    HANDLE duplicate;
    BYTE buffer[128];
    check((ULONG)set_thread(GetCurrentThread(),7,&enable,0)==0xc0000004,"alignment invalid length");
    check((ULONG)set_thread(GetCurrentThread(),7,NULL,1)==0xc0000005,"alignment NULL data");
    check((ULONG)set_thread(GetCurrentThread(),7,(void *)1,1)==0xc0000005,"alignment unreadable data");
    check((ULONG)set_thread((HANDLE)(uintptr_t)0xdeadbeef,7,&enable,1)==0xc0000008,"alignment invalid handle");
    check(DuplicateHandle(GetCurrentProcess(),GetCurrentThread(),GetCurrentProcess(),
                          &duplicate,0,FALSE,DUPLICATE_SAME_ACCESS),"duplicate current thread");
    check(set_thread(duplicate,7,&enable,1)==0,"alignment current-thread real handle");
    CloseHandle(duplicate);
    check((ULONG)set_thread(GetCurrentThread(),17,&returned,4)==0xc0000004,"debug-hide invalid length");
    check((ULONG)set_thread(GetCurrentProcess(),17,NULL,0)==0xc0000024,"debug-hide wrong object type");
    check(set_thread(GetCurrentThread(),17,NULL,0)==0,"debug-hide valid request");
    enable=FALSE;
    check(query_thread(GetCurrentThread(),17,&enable,1,NULL)==0 && enable,"debug-hide query state");
    check((ULONG)query_process(GetCurrentProcess(),0,buffer,0,&returned)==0xc0000004,
          "process basic information length validation");
    check(query_thread(GetCurrentThread(),0,buffer,48,&returned)==0,
          "thread basic information query");
}

static void test_resources_and_exports(HMODULE ntdll)
{
    resource_fn search=(resource_fn)GetProcAddress(ntdll,"LdrResSearchResource");
    ULONG_PTR path[3]={16,1,0};
    void *buffer=NULL;
    SIZE_T size=0;
    IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER *)ntdll;
    IMAGE_NT_HEADERS *nt=(IMAGE_NT_HEADERS *)((BYTE *)ntdll+dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exp=(IMAGE_EXPORT_DIRECTORY *)((BYTE *)ntdll+
                       nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD *names=(DWORD *)((BYTE *)ntdll+exp->AddressOfNames);
    unsigned i,visible=0;
    check(search!=NULL,"resource search exported");
    if(search) check(search(ntdll,path,3,0,&buffer,&size,NULL,NULL)==0 && buffer && size>52,
                     "version resource search returns bytes");
    check(GetProcAddress(ntdll,"wine_get_version")==NULL,"API version export hidden");
    for(i=0;i<exp->NumberOfNames;i++)
        if(!strcmp((char *)ntdll+names[i],"wine_get_version") ||
           !strcmp((char *)ntdll+names[i],"wine_get_build_id") ||
           !strcmp((char *)ntdll+names[i],"wine_get_host_version")) ++visible;
    check(visible==0,"direct PE version exports hidden");
}

static void test_sandbox_token(void)
{
    HANDLE token=NULL;
    query_fn query=(query_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQueryInformationToken");
    ULONG value=0xdeadbeef, returned=0;
    check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token),"open process token");
    check((ULONG)query(token,47,&value,0,&returned)==0xc0000023 && returned==4,
          "sandbox-token buffer length");
    check(query(token,47,&value,4,&returned)==0 && value==0 && returned==4,
          "ordinary token is not sandboxed");
    check((ULONG)query((HANDLE)(uintptr_t)0xdeadbeef,47,&value,4,&returned)==0xc0000008,
          "sandbox-token invalid handle");
    check((ULONG)query(GetCurrentProcess(),47,&value,4,&returned)==0xc0000024,
          "sandbox-token wrong object type");
    check((ULONG)query(token,47,NULL,4,&returned)==0xc0000005,
          "sandbox-token NULL output");
    CloseHandle(token);
}

static void record_sweeps(void)
{
    FILE *f=fopen("accuracy-statuses.csv","w");
    BYTE buffer[512];
    ULONG i,len,returned;
    NTSTATUS status;
    if(!f) { check(0,"open sweep CSV"); return; }
    fprintf(f,"api,class,length,status,return_length\n");
    for(i=0;i<=0x73;i++)
        for(len=0;len<=8;len+=4)
        {
            returned=0xdeadbeef; memset(buffer,0xcc,sizeof(buffer));
            status=query_process(GetCurrentProcess(),i,buffer,len,&returned);
            fprintf(f,"process,%lu,%lu,%08lx,%lu\n",i,len,(ULONG)status,returned);
        }
    for(i=0;i<=0x3b;i++)
        for(len=0;len<=8;len+=4)
        {
            returned=0xdeadbeef; memset(buffer,0xcc,sizeof(buffer));
            status=query_thread(GetCurrentThread(),i,buffer,len,&returned);
            fprintf(f,"thread,%lu,%lu,%08lx,%lu\n",i,len,(ULONG)status,returned);
        }
    fclose(f);
}

int main(void)
{
    HMODULE ntdll=GetModuleHandleA("ntdll.dll");
    HANDLE thread;
    unsigned i;
    BOOLEAN enable=TRUE;
    set_thread=(set_thread_fn)GetProcAddress(ntdll,"NtSetInformationThread");
    query_thread=(query_fn)GetProcAddress(ntdll,"NtQueryInformationThread");
    query_process=(query_fn)GetProcAddress(ntdll,"NtQueryInformationProcess");
    setvbuf(stdout,NULL,_IONBF,0);
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    AddVectoredExceptionHandler(1,handler);
    record_sweeps();
    test_statuses();
    test_resources_and_exports(ntdll);
    for(i=0;i<sizeof(moves)/sizeof(moves[0]);i++)
    {
        test_move(&moves[i],0,0);
        test_move(&moves[i],1,1);
    }
    set_thread(GetCurrentThread(),7,&enable,1);
    thread=CreateThread(NULL,0,worker,NULL,0,NULL);
    check(thread!=NULL,"create isolation-test thread");
    if(thread) { WaitForSingleObject(thread,INFINITE); CloseHandle(thread); }
    enable=FALSE; set_thread(GetCurrentThread(),7,&enable,1);
    test_sandbox_token();
    printf("RESULT: %u checks, %u failures\n",checks,failures);
    return failures ? 1 : 0;
}
