/* Original synthetic AMD64 unwind records and output-parameter probe. */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
typedef NTSTATUS (WINAPI *unwind_fn)(ULONG,ULONG64,ULONG64,RUNTIME_FUNCTION *,CONTEXT *,BOOLEAN *,void **,ULONG64 *,KNONVOLATILE_CONTEXT_POINTERS *,ULONG64 *,ULONG64 *,void **,ULONG);
int main(void)
{
 BYTE *image=VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);if(!image)return 2;
 unwind_fn unwind=(unwind_fn)(uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),"RtlVirtualUnwind2");if(!unwind)return 3;
 setvbuf(stdout,NULL,_IONBF,0);memset(image,0x90,4096);unsigned failures=0;
 for(unsigned which=0;which<4;++which)for(unsigned type=0;type<2;++type){
  DECLSPEC_ALIGN(16) ULONG64 stack[32];CONTEXT c;RUNTIME_FUNCTION f;BOOLEAN mach=0x7f;void *data=(void *)0xdeadbeef,*handler=(void *)0xdeadbeef;ULONG64 frame=0xdeadbeef;
  memset(&c,0,sizeof(c));memset(stack,0,sizeof(stack));memset(image+0x100,0,32);
  f.BeginAddress=0x200;f.EndAddress=0x210;f.UnwindData=0x100;image[0x100]=1;
  c.ContextFlags=CONTEXT_FULL;c.Rip=(uintptr_t)(image+0x204);c.Rsp=(uintptr_t)stack;c.EFlags=0x246;
  ULONG64 expected=(uintptr_t)(image+0x280);stack[0]=expected;image[0x20f]=0xc3;
  if(which==2){image[0x102]=1;image[0x104]=0;image[0x105]=0x0a;stack[1]=0x33;stack[2]=0x202;stack[3]=(uintptr_t)&stack[12];stack[4]=0x2b;}
  if(which==3){image[0x101]=1;image[0x102]=1;image[0x104]=1;image[0x105]=0x32;image[0x20a]=0x48;image[0x20b]=0x83;image[0x20c]=0xc4;image[0x20d]=0x20;image[0x20e]=0xc3;c.Rip=(uintptr_t)(image+0x20a);stack[4]=expected;}
  NTSTATUS status=unwind(type,(uintptr_t)image,c.Rip,which?&f:NULL,&c,&mach,&data,&frame,NULL,NULL,NULL,&handler,0);
  printf("CASE=%u type=%u status=%08lx mach=%u rip_match=%d rsp_delta=%lld frame_delta=%lld data=%p handler=%p flags=%08lx\n",which,type,status,mach,c.Rip==expected,(long long)(c.Rsp-(uintptr_t)stack),(long long)(frame-(uintptr_t)stack),data,handler,c.ContextFlags);
  if(status || c.Rip!=expected)++failures;
 }
 VirtualFree(image,0,MEM_RELEASE);printf("RESULT: 8 cases, %u basic failures\n",failures);return failures?1:0;
}
