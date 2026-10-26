/* Original API test. No client application code. */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
typedef NTSTATUS (WINAPI *query_fn)(HANDLE,ULONG,void *,ULONG,ULONG *);
typedef NTSTATUS (WINAPI *wait_fn)(HANDLE,BOOLEAN,const LARGE_INTEGER *);
struct last_call { void *first; USHORT number; unsigned char pad[6]; ULONGLONG time; };
static unsigned checks,failures;
static void check(int ok,const char *s) { ++checks;if(!ok)++failures;printf("%s %s\n",ok?"PASS":"FAIL",s); }
int main(int argc,char **argv)
{
 if(argc==1) freopen("C:\\tuxblox-probes\\lastcall-result.log","w",stdout);
 HMODULE n=GetModuleHandleA("ntdll.dll");
 query_fn query=(query_fn)(uintptr_t)GetProcAddress(n,"NtQueryInformationThread");
 wait_fn wait=(wait_fn)(uintptr_t)GetProcAddress(n,"NtWaitForSingleObject");
 setvbuf(stdout,NULL,_IONBF,0);
 if(argc==4 && !strcmp(argv[1],"--child")) {
  HANDLE ready=(HANDLE)(uintptr_t)strtoull(argv[2],NULL,16),stop=(HANDLE)(uintptr_t)strtoull(argv[3],NULL,16);
  SetEvent(ready);return wait(stop,FALSE,NULL)?2:0;
 }
 SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};
 HANDLE ready=CreateEventA(&sa,TRUE,FALSE,NULL),stop=CreateEventA(&sa,TRUE,FALSE,NULL),context=NULL,limited=NULL;
 STARTUPINFOA si={0};PROCESS_INFORMATION pi={0};char path[MAX_PATH],cmd[2*MAX_PATH];
 struct last_call out;ULONG len;NTSTATUS status;DWORD code=1;
 si.cb=sizeof(si);GetModuleFileNameA(NULL,path,sizeof(path));
 snprintf(cmd,sizeof(cmd),"\"%s\" --child %llx %llx",path,(unsigned long long)(uintptr_t)ready,(unsigned long long)(uintptr_t)stop);
 check(CreateProcessA(NULL,cmd,NULL,NULL,TRUE,0,NULL,NULL,&si,&pi),"create child");
 if(!pi.hProcess)return 2;
 check(WaitForSingleObject(ready,10000)==WAIT_OBJECT_0,"child reaches wait");Sleep(40);
 for(unsigned attempt=0;attempt<3;++attempt) {
  memset(&out,0xa5,sizeof(out));len=0xdeadbeef;status=query(pi.hThread,21,&out,sizeof(out),&len);
  printf("REMOTE status=%08lx length=%lu first=%p expected=%p number=%u time=%llu\n",status,len,out.first,stop,out.number,(unsigned long long)out.time);
  check(!status,"query waiting child in another process");
  if(!status){check(out.first==stop,"first argument is child's actual wait handle");check(len==sizeof(out),"returned length is 24");check(out.pad[0]==0xa5 && out.pad[5]==0xa5,"padding preserved");}
 }
 check(DuplicateHandle(GetCurrentProcess(),pi.hThread,GetCurrentProcess(),&context,THREAD_GET_CONTEXT,FALSE,0),"open with GET_CONTEXT only");
 status=query(context,21,&out,sizeof(out),&len);printf("CONTEXT_ONLY status=%08lx\n",status);check(!status,"GET_CONTEXT is sufficient");
 check(DuplicateHandle(GetCurrentProcess(),pi.hThread,GetCurrentProcess(),&limited,THREAD_QUERY_INFORMATION,FALSE,0),"open with QUERY_INFORMATION only");
 status=query(limited,21,&out,sizeof(out),&len);printf("QUERY_ONLY status=%08lx\n",status);check((ULONG)status==0xc0000022,"query right alone is denied");
 status=query((HANDLE)(LONG_PTR)-2,21,&out,sizeof(out),&len);check((ULONG)status==0xc000000d,"query current thread is invalid parameter");
 len=0xdeadbeef;status=query(pi.hThread,21,&out,32,&len);check((ULONG)status==0xc0000004 && len==0xdeadbeef,"invalid length preserves return length");
 memset(&out,0xa5,sizeof(out));len=0xdeadbeef;status=query(pi.hThread,21,&out,16,&len);check(!status && len==16,"legacy 16-byte structure supported");
 SetEvent(stop);check(WaitForSingleObject(pi.hProcess,10000)==WAIT_OBJECT_0,"child exits normally");GetExitCodeProcess(pi.hProcess,&code);check(!code,"child wait succeeded");
 if(code==STILL_ACTIVE)TerminateProcess(pi.hProcess,2);
 CloseHandle(context);CloseHandle(limited);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);CloseHandle(ready);CloseHandle(stop);
 printf("RESULT: %u checks, %u failures\n",checks,failures);return failures?1:0;
}
