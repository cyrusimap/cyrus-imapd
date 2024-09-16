#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

PROGRAMS=lemming gdbtramp crash syslog_probe
LIBS=syslog.so

CC=gcc
COPTFLAGS=-g -O0
CWARNFLAGS=-Wall -Wextra
CFLAGS=$(COPTFLAGS) $(CWARNFLAGS) -fPIC

all: $(PROGRAMS) $(LIBS)

lemming_SOURCE=lemming.c
lemming_OBJS=$(lemming_SOURCE:.c=.o)
lemming: $(lemming_OBJS)
	$(LINK.c) -o $@ $(lemming_OBJS)

gdbtramp_SOURCE=gdbtramp.c
gdbtramp_OBJS=$(gdbtramp_SOURCE:.c=.o)
gdbtramp: $(gdbtramp_OBJS)
	$(LINK.c) -o $@ $(gdbtramp_OBJS)

crash_SOURCE=crash.c
crash_OBJS=$(crash_SOURCE:.c=.o)
crash: $(crash_OBJS)
	$(LINK.c) -o $@ $(crash_OBJS)

syslog_probe_SOURCE=syslog_probe.c
syslog_probe_OBJS=$(syslog_probe_SOURCE:.c=.o)
syslog_probe: $(syslog_probe_OBJS)
	$(LINK.c) -o $@ $(syslog_probe_OBJS)

syslog_SOURCE=syslog.c
syslog_OBJS=$(syslog_SOURCE:.c=.o)
syslog.so: $(syslog_OBJS)
	$(LINK.c) -shared -o $@ $(syslog_OBJS) -ldl

clean:
	$(RM) $(PROGRAMS) $(LIBS) *.o
