/* Original Windows image metadata API probe. No application code. */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
typedef NTSTATUS (WINAPI *query_fn)(HANDLE,const void *,ULONG,void *,SIZE_T,SIZE_T *);
struct extension { ULONG type,flags; void *rva; SIZE_T size; };
static query_fn query;
static void probe(const char *name,void *address)
{
 static const SIZE_T lengths[]={0,16,23,24,32};
 unsigned char bytes[64];SIZE_T ret;NTSTATUS status;
 printf("ADDRESS name=%s value=%p\n",name,address);
 memset(bytes,0,sizeof(bytes));ret=0xdeadbeef;
 status=query((HANDLE)(LONG_PTR)-1,address,6,bytes,24,&ret);
 printf("IMAGE status=%08lx return=%llu bytes=",status,(unsigned long long)ret);
 for(unsigned i=0;i<24;++i)printf("%02x",bytes[i]);puts("");
 for(ULONG type=0;type<4;++type)for(unsigned j=0;j<sizeof(lengths)/sizeof(lengths[0]);++j) {
  struct extension out;
  memset(bytes,0,sizeof(bytes));memcpy(bytes,&type,sizeof(type));ret=0xdeadbeef;
  status=query((HANDLE)(LONG_PTR)-1,address,14,bytes,lengths[j],&ret);
  memcpy(&out,bytes,sizeof(out));
  printf("EXT name=%s type=%lu length=%llu status=%08lx return=%llu flags=%08lx rva=%p size=%llu raw=",name,type,(unsigned long long)lengths[j],status,(unsigned long long)ret,out.flags,out.rva,(unsigned long long)out.size);
  for(unsigned i=0;i<32;++i)printf("%02x",bytes[i]);puts("");
 }
}
int main(void)
{
 setvbuf(stdout,NULL,_IONBF,0);
 query=(query_fn)(uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQueryVirtualMemory");
 if(!query)return 2;
 probe("ntdll",GetModuleHandleA("ntdll.dll"));probe("kernel32",GetModuleHandleA("kernel32.dll"));probe("self",GetModuleHandleA(NULL));
 void *private=VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
 if(!private)return 2;
 probe("private",private);probe("null",NULL);VirtualFree(private,0,MEM_RELEASE);return 0;
}
