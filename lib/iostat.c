#include <stdio.h>
#include <sys/types.h>
#include <syslog.h>
#include "config.h"
#include "libconfig.h"
#include "iostat.h"
#include "util.h"

EXPORTED void read_io_count(struct io_count *iocount) {
    FILE *file = NULL;
    char buf[64] = "";

    if ((file = fopen("/proc/self/io", "r")) != NULL ) {
        while(fgets(buf,sizeof(buf),file)) {
            //syslog(LOG_DEBUG,"/proc/self/io content:%s",buf);
            sscanf(buf,"read_bytes:%d",&(iocount->io_read_count));
            sscanf(buf,"write_bytes:%d",&(iocount->io_write_count));
        }
        fclose (file);
        return;
    }
    else {
        xsyslog_ev(LOG_ERR, "iostat.open.failed",
                   lf_s("sys.path", "/proc/self/io"));
        config_iolog = 0;
        xsyslog_ev(LOG_ERR, "iostat.disabled");
    }
}

