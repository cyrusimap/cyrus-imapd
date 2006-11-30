#include <stdio.h>
#include "../imapurl.h"

void fatal(const char* s, int code)
{
      fprintf(stderr, "imapurl: %s\r\n", s);
      exit(code);
}

int main(void)
{
    struct imapurl imapurl;
    char url[400];

    memset(&imapurl, 0, sizeof(struct imapurl));
    imapurl.server = "server";
    imapurl.auth = "*";
    imapurl.mailbox = "&AOQ- &AMQ-";  /* "ä Ä" */
    imapurl.uidvalidity = 1234567890;

    puts(imapurl.mailbox);
    imapurl_toURL(url, &imapurl);
    puts(url);
    imapurl_fromURL(&imapurl, url);
    puts(imapurl.mailbox);
    printf("%lu\n", imapurl.uidvalidity);
    free(imapurl.freeme);

    return 0;
}

