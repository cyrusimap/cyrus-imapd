# Makefile for cyrus documentation directory
# 
#	(C) Copyright 1995 by Carnegie Mellon University
# 
#                      All Rights Reserved
# 
# Permission to use, copy, modify, distribute, and sell this software
# and its documentation for any purpose is hereby granted without
# fee, provided that the above copyright notice appear in all copies
# and that both that copyright notice and this permission notice
# appear in supporting documentation, and that the name of Carnegie
# Mellon University not be used in advertising or publicity
# pertaining to distribution of the software without specific,
# written prior permission.  Carnegie Mellon University makes no
# representations about the suitability of this software for any
# purpose.  It is provided "as is" without express or implied
# warranty.
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
# SOFTWARE.
# 

all: htmlstrip docs clean

DOCS= README install overview changes

docs: $(DOCS)

htmlstrip: html/htmlstrip.c
	$(CC) $(CFLAGS) -o htmlstrip html/htmlstrip.c

README: html/readme.html htmlstrip
	./htmlstrip html/readme.html > README

install: html/install.html htmlstrip
	./htmlstrip html/install.html > install

overview: html/overview.html htmlstrip
	./htmlstrip html/overview.html > overview

changes: html/changes.html htmlstrip
	./htmlstrip html/changes.html > changes

clean:
	rm -f *.o *~ Makefile.bak htmlstrip

realclean: clean
	rm -f $(DOCS)

distclean: clean

depend:

# DO NOT DELETE THIS LINE -- make depend depends on it.


