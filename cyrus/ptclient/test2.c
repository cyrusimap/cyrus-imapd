#include <stdio.h>
#include <sys/syslog.h>

int main(void) {
  char cacheid[16]="4224423";
  openlog("testr", LOG_PID,LOG_LOCAL6);
  
  if (!auth_setid("cg2v@club.cc.cmu.edu",cacheid))
    printf ("Auth_memberof(cg2v,cg2v:me) is %d\n",
            auth_memberof("cg2v:me"));
  
  else
    printf ("Auth_setid(cg2v@club.cc.cmu.edu) failed\n");
  
}

int fatal(char *foo) {
  fprintf(stderr, "Fatal error: %s\n", foo);
  exit(1);
}
