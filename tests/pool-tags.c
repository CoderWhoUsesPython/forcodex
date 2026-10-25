/* Original system-pool query contract probe; no application code. */
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

typedef NTSTATUS (WINAPI *query_fn)(ULONG,void *,ULONG,ULONG *);
typedef struct {
    ULONG tag, paged_allocs, paged_frees;
    SIZE_T paged_used;
    ULONG nonpaged_allocs, nonpaged_frees;
    SIZE_T nonpaged_used;
} pool_entry;
typedef struct { ULONG count; pool_entry entries[1]; } pool_info;
static unsigned checks, failures;
static void check(int ok,const char *name)
{ ++checks; if (!ok) ++failures; printf("%s %s\n",ok?"PASS":"FAIL",name); }
int main(void)
{
    const ULONG sizes[]={0,1,4,7,8,16,40,48,4096,1024*1024};
    query_fn query=(query_fn)(void *)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQuerySystemInformation");
    ULONG returned, count=0, size=4096;
    NTSTATUS status;
    void *buffer=HeapAlloc(GetProcessHeap(),0,1024*1024);
    unsigned i;
    setvbuf(stdout,NULL,_IONBF,0);
    if (!query || !buffer) return 2;
    printf("LAYOUT entry=%llu offset=%llu\n",(unsigned long long)sizeof(pool_entry),
           (unsigned long long)offsetof(pool_info,entries));
    for(i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++) {
        returned=0xdeadbeef;
        memset(buffer,0xcc,1024*1024);
        status=query(22,buffer,sizes[i],&returned);
        printf("QUERY length=%lu status=%08lx returned=%lu header=%08lx\n",
               sizes[i],status,returned,*(ULONG *)buffer);
    }
    for(i=0;i<3;i++) {
        ULONG n=i==0?0:i==1?8:4096;
        returned=0xdeadbeef;
        status=query(22,NULL,n,&returned);
        printf("NULL length=%lu status=%08lx returned=%lu\n",n,status,returned);
    }
    for(i=0;i<12;i++) {
        void *p=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,size);
        if(!p) return 2;
        returned=0xdeadbeef;
        status=query(22,p,size,&returned);
        printf("GROW length=%lu status=%08lx returned=%lu\n",size,status,returned);
        if(status>=0) {
            count=((pool_info *)p)->count;
            check(returned<=size,"successful result fits supplied buffer");
            check(returned>=offsetof(pool_info,entries),"successful result includes header");
            check(count<=(returned>=8?(returned-8)/sizeof(pool_entry):0),"entry count fits returned bytes");
            printf("SUCCESS count=%lu\n",count);
            HeapFree(GetProcessHeap(),0,p);
            break;
        }
        HeapFree(GetProcessHeap(),0,p);
        if((ULONG)status!=0xc0000004 && (ULONG)status!=0xc0000023) break;
        if(returned>8*1024*1024) break;
        size=returned>size?returned+4096:size*2;
    }
    check(status>=0,"pool information query completes");
    HeapFree(GetProcessHeap(),0,buffer);
    printf("RESULT: %u checks, %u failures\n",checks,failures);
    return failures?1:0;
}
