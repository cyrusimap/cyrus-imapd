/*
 * Configuration routines
 */

extern int config_init();
extern char *config_getstring();
extern int config_getint();
extern int config_getswitch();
extern char *config_partitiondir();

/* Values of mandatory options */
extern char *config_dir;
extern char *config_defpartition;

