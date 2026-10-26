/* Original exception extended-context layout probe. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
struct chunk { LONG offset; ULONG length; };
struct context_ex { struct chunk all,legacy,xstate; };
static BYTE *active,*resume;
static unsigned count,failures;
static LONG CALLBACK handler(EXCEPTION_POINTERS *p)
{
 CONTEXT *c=p->ContextRecord;
 if((uintptr_t)c->Rip!=(uintptr_t)active)return EXCEPTION_CONTINUE_SEARCH;
 ++count;
 printf("EXCEPTION n=%u code=%08lx flags=%08lx ctx=%p rsp=%llx\n",count,p->ExceptionRecord->ExceptionCode,c->ContextFlags,c,(unsigned long long)c->Rsp);
 if(c->ContextFlags&0x40) {
  struct context_ex ex;memcpy(&ex,(BYTE *)c+sizeof(*c),sizeof(ex));
  uintptr_t xs=(uintptr_t)c+sizeof(*c)+ex.xstate.offset;
  int valid=ex.all.offset==-(LONG)sizeof(*c) && ex.all.length>=sizeof(*c) && ex.all.length<1024*1024 && xs>=(uintptr_t)c && !(xs&63) && xs+ex.xstate.length<=(uintptr_t)c+ex.all.length;
  printf("XSTATE all_offset=%ld all_length=%lu legacy_offset=%ld legacy_length=%lu xstate_offset=%ld xstate_length=%lu aligned=%d valid=%d\n",ex.all.offset,ex.all.length,ex.legacy.offset,ex.legacy.length,ex.xstate.offset,ex.xstate.length,!(xs&63),valid);
  if(!valid)++failures;
 } else puts("XSTATE absent");
 c->Rip=(uintptr_t)resume;return EXCEPTION_CONTINUE_EXECUTION;
}
int main(void)
{
 setvbuf(stdout,NULL,_IONBF,0);
 BYTE *code=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
 void *veh=AddVectoredExceptionHandler(1,handler);if(!code||!veh)return 2;
 code[0]=0x0f;code[1]=0x0b;code[2]=0xc3;active=code;resume=code+2;
 FlushInstructionCache(GetCurrentProcess(),code,3);
 for(unsigned i=0;i<4;++i)((void(*)(void))(uintptr_t)code)();
 RemoveVectoredExceptionHandler(veh);VirtualFree(code,0,MEM_RELEASE);
 printf("RESULT: exceptions=%u layout_failures=%u\n",count,failures);return count==4&&!failures?0:1;
}
