/* Wine-local integration test for real ExAllocatePoolWithTag accounting. */
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef NTSTATUS (WINAPI *query_fn)(ULONG,void *,ULONG,ULONG *);
typedef void *(WINAPI *alloc_fn)(int,SIZE_T,ULONG);
typedef void (WINAPI *free_fn)(void *,ULONG);
typedef struct { ULONG tag,pa,pf; SIZE_T pu; ULONG na,nf; SIZE_T nu; } entry;
typedef struct { ULONG count; entry tags[1]; } info;
typedef struct { ULONG_PTR address; SIZE_T size; ULONG tag; } big_entry;
typedef struct { ULONG count; big_entry entries[1]; } big_info;
static HMODULE pool_module;
static query_fn query;
static alloc_fn allocate;
static free_fn release;
static unsigned checks,failures;
static volatile LONG thread_failures;
static void check(int ok,const char *name)
{ ++checks; if(!ok) ++failures; printf("%s %s\n",ok?"PASS":"FAIL",name); }
static int load_pool(void)
{
    HMODULE n=pool_module=LoadLibraryA("ntoskrnl.exe");
    query=(query_fn)(void *)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQuerySystemInformation");
    if(!n) { printf("LoadLibrary error=%lu\n",GetLastError()); return 0; }
    allocate=(alloc_fn)(void *)GetProcAddress(n,"ExAllocatePoolWithTag");
    release=(free_fn)(void *)GetProcAddress(n,"ExFreePoolWithTag");
    return query&&allocate&&release;
}
static int get_tag(ULONG tag,entry *out)
{
    ULONG size=4096,needed=0,i;
    unsigned attempts;
    memset(out,0,sizeof(*out));
    for(attempts=0;attempts<12;attempts++) {
        info *p=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,size);
        NTSTATUS status;
        if(!p) return 0;
        status=query(22,p,size,&needed);
        if(status>=0) {
            for(i=0;i<p->count;i++) if(p->tags[i].tag==tag) { *out=p->tags[i]; break; }
            HeapFree(GetProcessHeap(),0,p); return 1;
        }
        HeapFree(GetProcessHeap(),0,p);
        if((ULONG)status!=0xc0000004 && (ULONG)status!=0xc0000023) return 0;
        size=needed>size?needed+1024:size*2;
    }
    return 0;
}
static int find_big(void *address,big_entry *out)
{
    ULONG size=4096,needed=0,i;
    unsigned attempts;
    for(attempts=0;attempts<12;attempts++) {
        big_info *p=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,size);
        NTSTATUS status;
        if(!p) return -1;
        status=query(66,p,size,&needed);
        if(status>=0) {
            for(i=0;i<p->count;i++) if((p->entries[i].address&~(ULONG_PTR)1)==(ULONG_PTR)address) {
                *out=p->entries[i]; HeapFree(GetProcessHeap(),0,p); return 1;
            }
            HeapFree(GetProcessHeap(),0,p); return 0;
        }
        HeapFree(GetProcessHeap(),0,p);
        if((ULONG)status!=0xc0000004 && (ULONG)status!=0xc0000023) return -1;
        size=needed>size?needed+1024:size*2;
    }
    return -1;
}
static DWORD WINAPI worker(void *arg)
{
    unsigned i; (void)arg;
    for(i=0;i<100;i++) {
        void *p=allocate(i&1,17+i,0x54586443);
        if(!p) { InterlockedIncrement(&thread_failures); continue; }
        memset(p,0x5a,17+i);
        release(p,0x54586443);
    }
    return 0;
}
int main(int argc,char **argv)
{
    entry before,after;
    void *p,*n,*large[3];
    big_entry big;
    MEMORY_BASIC_INFORMATION memory;
    HANDLE threads[4],ready,done;
    unsigned i;
    char rname[80],dname[80],exe[MAX_PATH],command[2*MAX_PATH];
    STARTUPINFOA si={sizeof(si)};
    PROCESS_INFORMATION pi={0};
    setvbuf(stdout,NULL,_IONBF,0);
    if(!load_pool()) return 2;
    if(argc==4 && !strcmp(argv[1],"child")) {
        ready=OpenEventA(EVENT_MODIFY_STATE,FALSE,argv[2]);
        done=OpenEventA(SYNCHRONIZE,FALSE,argv[3]);
        p=allocate(0,3456,0x32586443);
        n=allocate(512,8193,0x32586443);
        if(!ready || !done || !p || !n) return 3;
        printf("CHILD_POINTER_BITS=%u\n",(unsigned)(8*sizeof(void *)));
        SetEvent(ready);
        WaitForSingleObject(done,15000);
        ExitProcess(0); /* Deliberately let process cleanup release this pool. */
    }
    check(get_tag(0x31586443,&before),"query baseline tag");
    p=allocate(1,1234,0x31586443); n=allocate(0,2345,0x31586443);
    check(p&&n,"allocate paged and nonpaged pool");
    check(get_tag(0x31586443,&after),"query allocated tag");
    check(after.pa==before.pa+1 && after.pu==before.pu+1234,"paged allocation count and bytes");
    check(after.na==before.na+1 && after.nu==before.nu+2345,"nonpaged allocation count and bytes");
    if(p) release(p,0x31586443);
    if(n) release(n,0x31586443);
    check(get_tag(0x31586443,&after),"query freed tag");
    check(after.pf==before.pf+1 && after.pu==before.pu,"paged free count and bytes");
    check(after.nf==before.nf+1 && after.nu==before.nu,"nonpaged free count and bytes");
    check(get_tag(0x42586443,&before),"query large allocation baseline");
    large[0]=allocate(1,8097,0x42586443);
    large[1]=allocate(0,8192,0x42586443);
    large[2]=allocate(512,8193,0x42586443);
    check(large[0]&&large[1]&&large[2],"allocate large paged, executable and NX pools");
    for(i=0;i<3;i++) {
        check(large[i] && !((uintptr_t)large[i]&4095),"large pool allocation is page aligned");
        check(find_big(large[i],&big)==1 && big.tag==0x42586443 &&
              (big.address&1)==(i?1:0) && big.size==(i==2?12288:8192),
              "big pool reports address, type, tag and committed bytes");
        VirtualQuery(large[i],&memory,sizeof(memory));
        check(memory.Protect==(i==1?PAGE_EXECUTE_READWRITE:PAGE_READWRITE),
              "large pool respects executable versus NX type");
    }
    check(get_tag(0x42586443,&after) && after.pu==before.pu+8192 && after.nu==before.nu+20480,
          "pool tags count actual committed large pool bytes");
    {
        unsigned char partial[32]; ULONG needed=0;
        NTSTATUS status=query(66,partial,sizeof(partial),&needed);
        check((ULONG)status==0xc0000004 && needed>=80 && *(ULONG *)partial>=3,
              "undersized big-pool query reports full required size");
    }
    for(i=0;i<3;i++) {
        if(large[i]) release(large[i],0x42586443);
        check(find_big(large[i],&big)==0,"freed large pool disappears from enumeration");
    }
    check(get_tag(0x42586443,&after) && after.pf==before.pf+1 && after.nf==before.nf+2 &&
          after.pu==before.pu && after.nu==before.nu,"large pool frees balance committed bytes");
    check(get_tag(0x54586443,&before),"query concurrency baseline");
    for(i=0;i<4;i++) threads[i]=CreateThread(NULL,0,worker,NULL,0,NULL);
    check(WaitForMultipleObjects(4,threads,TRUE,15000)==WAIT_OBJECT_0,"concurrent pool workers finish");
    for(i=0;i<4;i++) if(threads[i]) CloseHandle(threads[i]);
    check(!thread_failures && get_tag(0x54586443,&after),"query concurrent allocations");
    check(after.pa==before.pa+200 && after.pf==before.pf+200 && after.pu==before.pu &&
          after.na==before.na+200 && after.nf==before.nf+200 && after.nu==before.nu,
          "concurrent allocation/free totals balance");
    check(get_tag(0x32586443,&before),"query child baseline");
    snprintf(rname,sizeof(rname),"Local\\PoolReady%lu",GetCurrentProcessId());
    snprintf(dname,sizeof(dname),"Local\\PoolDone%lu",GetCurrentProcessId());
    ready=CreateEventA(NULL,TRUE,FALSE,rname); done=CreateEventA(NULL,TRUE,FALSE,dname);
    if(argc==3 && !strcmp(argv[1],"--child32")) {
        if(strlen(argv[2])>=sizeof(exe)) return 2;
        strcpy(exe,argv[2]);
    } else GetModuleFileNameA(NULL,exe,sizeof(exe));
    snprintf(command,sizeof(command),"\"%s\" child %s %s",exe,rname,dname);
    if(CreateProcessA(NULL,command,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)) {
        check(WaitForSingleObject(ready,10000)==WAIT_OBJECT_0,"child allocation becomes ready");
        check(get_tag(0x32586443,&after) && after.na==before.na+2 && after.nu==before.nu+15744,
              "query sees another process allocation");
        SetEvent(done);
        if(WaitForSingleObject(pi.hProcess,10000)!=WAIT_OBJECT_0) TerminateProcess(pi.hProcess,4);
        check(get_tag(0x32586443,&after) && after.nf==before.nf+2 && after.nu==before.nu,
              "process exit releases outstanding pool bytes");
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    } else check(0,"create pool allocation child");
    CloseHandle(ready); CloseHandle(done);
    check(get_tag(0x33586443,&before),"query module unload baseline");
    p=allocate(1,23,0x33586443); n=allocate(512,8193,0x33586443);
    check(p&&n,"allocate outstanding pools before module unload");
    check(FreeLibrary(pool_module),"unload kernel compatibility module");
    check(get_tag(0x33586443,&after) && after.pf==before.pf+1 && after.nf==before.nf+1 &&
          after.pu==before.pu && after.nu==before.nu,"module unload releases outstanding pool accounting");

    printf("RESULT: %u checks, %u failures\n",checks,failures);
    return failures?1:0;
}
