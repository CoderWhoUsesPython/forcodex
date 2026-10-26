/* Original instrumentation-callback exception-frame ABI probe. */
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef NTSTATUS (WINAPI *set_fn)(HANDLE,ULONG,void *,ULONG);
static volatile ULONGLONG capture[32];
static BYTE *active,*resume;
static ULONG reported_flags; static USHORT reported_cs,reported_ss;
static LONG CALLBACK handler(EXCEPTION_POINTERS *p)
{
 if((uintptr_t)p->ContextRecord->Rip!=(uintptr_t)active)return EXCEPTION_CONTINUE_SEARCH;
 reported_flags=p->ContextRecord->EFlags;reported_cs=p->ContextRecord->SegCs;reported_ss=p->ContextRecord->SegSs;
 p->ContextRecord->Rip=(uintptr_t)resume;return EXCEPTION_CONTINUE_EXECUTION;
}
static void emit(BYTE **p,const void *s,SIZE_T n){memcpy(*p,s,n);*p+=n;}
int main(void)
{
 static const ULONG offsets[]={0xf8,0x98,0x4f0,0x500,0x590,0x5a8,0x4d4,0x4e0,0x4e4,0x598,0x5a0,0x5b0,0x30};
 HMODULE n=GetModuleHandleA("ntdll.dll");
 set_fn set=(set_fn)(uintptr_t)GetProcAddress(n,"NtSetInformationProcess");
 void *dispatcher=(void *)(uintptr_t)GetProcAddress(n,"KiUserExceptionDispatcher");
 BYTE *code=VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE),*p=code,*skip;
 struct {ULONG version,reserved;void *callback;} info={0,0,code};
 NTSTATUS status;ULONGLONG imm;void *veh;
 setvbuf(stdout,NULL,_IONBF,0);if(!code||!set||!dispatcher)return 2;
 {static const BYTE a[]={0x9c,0x50,0x41,0x53,0x48,0xb8};emit(&p,a,sizeof(a));}
 imm=(uintptr_t)dispatcher;emit(&p,&imm,8);
 {static const BYTE a[]={0x49,0x39,0xc2,0x0f,0x85};emit(&p,a,sizeof(a));}
 skip=p;p+=4;
 {static const BYTE a[]={0x48,0x8d,0x44,0x24,0x18,0x49,0xbb};emit(&p,a,sizeof(a));}
 imm=(uintptr_t)capture;emit(&p,&imm,8);
 {static const BYTE a[]={0x49,0x89,0x03};emit(&p,a,sizeof(a));}
 for(unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);++i){
  static const BYTE load[]={0x48,0x8b,0x84,0x24},store[]={0x49,0x89,0x43};
  ULONG off=offsets[i]+24;BYTE dst=(BYTE)((i+1)*8);
  emit(&p,load,sizeof(load));emit(&p,&off,4);emit(&p,store,sizeof(store));emit(&p,&dst,1);
 }
 {static const BYTE a[]={0x48,0x8b,0x44,0x24,0x08,0x49,0x89,0x83,0x80,0,0,0,
  0x49,0x89,0x8b,0x88,0,0,0,0x49,0x89,0x93,0x90,0,0,0,
  0x4d,0x89,0x83,0x98,0,0,0,0x4d,0x89,0x8b,0xa0,0,0,0,
  0x4d,0x89,0x93,0xa8,0,0,0,0x48,0x8b,0x04,0x24,0x49,0x89,0x83,0xb0,0,0,0};emit(&p,a,sizeof(a));}
 {static const BYTE a[]={0x49,0xff,0x43,0x78};emit(&p,a,sizeof(a));}
 {LONG disp=(LONG)(p-(skip+4));memcpy(skip,&disp,4);}
 {static const BYTE a[]={0x41,0x5b,0x58,0x9d,0x41,0xff,0xe2};emit(&p,a,sizeof(a));}
 BYTE *trigger=code+1024;
 {static const BYTE a[]={0xb8,0x44,0x33,0x22,0x11,0xb9,0x55,0x44,0x33,0x22,
  0xba,0x66,0x55,0x44,0x33,0x41,0xb8,0x77,0x66,0x55,0x44,
  0x41,0xb9,0x88,0x77,0x66,0x55,0x41,0xba,0x99,0x88,0x77,0x66,
  0x41,0xbb,0xaa,0x99,0x88,0x77};memcpy(trigger,a,sizeof(a));active=trigger+sizeof(a);}
 active[0]=0x0f;active[1]=0x0b;active[2]=0xc3;resume=active+2;
 FlushInstructionCache(GetCurrentProcess(),code,4096);veh=AddVectoredExceptionHandler(1,handler);
 status=set((HANDLE)(LONG_PTR)-1,40,&info,sizeof(info));printf("SET_CALLBACK status=%08lx\n",status);
 if(status)return 3;
 ((void(*)(void))(uintptr_t)trigger)();
 info.callback=NULL;status=set((HANDLE)(LONG_PTR)-1,40,&info,sizeof(info));printf("CLEAR_CALLBACK status=%08lx\n",status);
 printf("FRAME count=%llu code=%08lx ctx_rip_matches=%d record_addr_matches=%d machine_rip_matches=%d stack_matches=%d\n",capture[15],(ULONG)capture[3],capture[1]==(uintptr_t)active,capture[4]==(uintptr_t)active,capture[5]==(uintptr_t)active,capture[2]==capture[6]);
 printf("DESCRIPTOR all_length=%lu xstate_offset=%ld xstate_length=%lu machine_cs=%llx machine_flags=%llx machine_ss=%llx ctxflags=%08lx\n",(ULONG)capture[7],(LONG)capture[8],(ULONG)capture[9],capture[10],capture[11],capture[12],(ULONG)capture[13]);
 printf("SEGMENTS context_cs=%x context_ss=%x context_flags=%lx cs_match=%d ss_match=%d flags_match=%d\n",reported_cs,reported_ss,reported_flags,capture[10]==reported_cs,capture[12]==reported_ss,capture[11]==reported_flags);
 printf("ENTRY rax=%llx rcx=%llx rdx=%llx r8=%llx r9=%llx r10=%llx r11=%llx\n",capture[16],capture[17],capture[18],capture[19],capture[20],capture[21],capture[22]);
 int valid=capture[15]==1 && capture[1]==(uintptr_t)active && capture[4]==(uintptr_t)active && capture[5]==(uintptr_t)active && capture[2]==capture[6];
 RemoveVectoredExceptionHandler(veh);VirtualFree(code,0,MEM_RELEASE);printf("RESULT: frame_valid=%d\n",valid);return valid?0:1;
}
