#include "../imapurl.h"

int main(void)
{
    char server[100] = "server";
    char mailbox[100] = "&AOQ- &AMQ-";  /* "ä Ä" */
    char url[100];

    puts(mailbox);
    imapurl_toURL(url, server, mailbox, 0);
    puts(url);
    imapurl_fromURL(server, mailbox, url);
    puts(mailbox);

    return 0;
}

