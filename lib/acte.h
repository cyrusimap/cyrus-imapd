struct acte_client {
    char *auth_type;
    int (*start)();
    int (*auth)();
    void (*free_state)();
}

struct acte_server {
    char *auth_type;
    int (*start)();
    int (*auth)();
    void (*query_state)();
    void (*free_state)();
}


#define ACTE_PROT_NONE 1
#define ACTE_PROT_INTEGRITY 2
#define ACTE_PROT_PRIVACY 4

#define ACTE_FAIL_SOFT 1	/* Try some other authentication method */
#define ACTE_FAIL_HARD 2	/* Don't try some other authentication method */
#define ACTE_DONE 3		/* Server has authenticated user */
