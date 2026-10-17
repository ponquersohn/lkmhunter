/* Linux x86_64 helper for read-only debugfs output collection.
 * Some rootkits, for example Singularity skips write(fd=0). Give the 
 * child a writable fd 0 and redirect stdout writes to it at syscall entry, 
 * including libc's internal writes.
 * Intended for debugfs -R: stdin is unavailable for interactive commands.
 * PTRACE_O_EXITKILL prevents the child surviving an unexpected tracer exit.
 */
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
int main(int argc,char **argv) {
 int debug = getenv("LKMHUNTER_DEBUGFS_DEBUG") &&
             getenv("LKMHUNTER_DEBUGFS_DEBUG")[0] == '1';
 unsigned long redirected = 0;
 if(argc<2) {fprintf(stderr,"usage: debugfs-output command [args...]\n");return 2;}
 pid_t p=fork();
 if(p<0) {perror("fork");return 1;}
 if(!p) {
  if(dup2(STDOUT_FILENO,STDIN_FILENO)<0) {perror("dup2");_exit(120);}
  if(ptrace(PTRACE_TRACEME,0,0,0)<0) {perror("PTRACE_TRACEME");_exit(121);}
  raise(SIGSTOP); execvp(argv[1],argv+1); perror("execvp");_exit(127);
 }
 int status;
 if(waitpid(p,&status,0)<0) {perror("initial waitpid");return 1;}
 if(WIFEXITED(status)) return WEXITSTATUS(status);
 if(WIFSIGNALED(status)) return 128+WTERMSIG(status);
 if(debug) fprintf(stderr,"debugfs-output: tracing child pid=%ld\n",(long)p);
 if(ptrace(PTRACE_SETOPTIONS,p,0,PTRACE_O_TRACESYSGOOD|PTRACE_O_EXITKILL)<0) {perror("options");return 1;}
 int sig=0;
 for(;;) {
  if(ptrace(PTRACE_SYSCALL,p,0,sig)<0) {perror("resume");return 1;}
  if(waitpid(p,&status,0)<0) {perror("wait");return 1;}
  if(WIFEXITED(status)) {
   if(debug) fprintf(stderr,"debugfs-output: child exit=%d redirected_writes=%lu\n",WEXITSTATUS(status),redirected);
   return WEXITSTATUS(status);
  }
  if(WIFSIGNALED(status)) {
   fprintf(stderr,"debugfs-output: child signal=%d redirected_writes=%lu\n",WTERMSIG(status),redirected);
   return 128+WTERMSIG(status);
  }
  sig=WSTOPSIG(status);
  if(sig==(SIGTRAP|0x80)) {
   struct user_regs_struct r;
   if(ptrace(PTRACE_GETREGS,p,0,&r)<0) {perror("PTRACE_GETREGS");return 1;}
   if(r.orig_rax==SYS_write && r.rax==(unsigned long long)-ENOSYS && r.rdi==1) {
    r.rdi=0;
    if(ptrace(PTRACE_SETREGS,p,0,&r)<0) {perror("PTRACE_SETREGS");return 1;}
    redirected++;
   }
   sig=0;
  } else if(sig==SIGTRAP) sig=0;
 }
}
