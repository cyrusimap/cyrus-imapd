/* amssync.h -- synchronize AMS bboard into IMAP
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */

typedef struct msg_struct{
    char name[256];
    time_t stamp;
} message;

typedef struct bbd_struct {
    char name[256];
    int alloced;
    int inuse;
    message *msgs;
} bboard;


int getams();
int getimap();
int cmpmsg();
void DeleteImap();
int UploadAMS();

