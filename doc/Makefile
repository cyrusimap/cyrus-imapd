# Makefile for cyrus documentation directory
# 
#	(C) Copyright 1995 by Carnegie Mellon University
# 
#                      All Rights Reserved
# 
# Permission to use, copy, modify, and distribute this software and its 
# documentation for any purpose and without fee is hereby granted, 
# provided that the above copyright notice appear in all copies and that
# both that copyright notice and this permission notice appear in 
# supporting documentation, and that the name of CMU not be
# used in advertising or publicity pertaining to distribution of the
# software without specific, written prior permission.  
# 
# CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
# ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
# CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
# ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
# ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
# SOFTWARE.
# 

.SUFFIXES: .txt .html

all: htmlstrip docs

htmlstrip: htmlstrip.c
	$(CC) $(CFLAGS) -o htmlstrip htmlstrip.c

.html.txt:
	./htmlstrip $< > $@

docs: install.txt overview.txt changes.txt README

README: readme.html
	./htmlstrip readme.html > README

clean:
	rm -f *.o *~ Makefile.bak htmlstrip

realclean: clean
	rm -f *.txt

distclean: clean

depend:

# DO NOT DELETE THIS LINE -- make depend depends on it.


