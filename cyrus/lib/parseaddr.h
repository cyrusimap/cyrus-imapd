struct address {
    char *name;
    char *route;
    char *mailbox;
    char *domain;
    struct address *next;
    char *freeme;
};


