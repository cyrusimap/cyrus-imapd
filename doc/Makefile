# Makefile for cyrus documentation directory
# 
# Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
# 
# This software is made available for academic and research
# purposes only.  No commercial license is hereby granted.
# Copying and other reproduction is authorized only for research,
# education, and other non-commercial purposes.  No warranties,
# either expressed or implied, are made regarding the operation,
# use, or results of the software.  Such a release does not permit
# use of the code for commercial purposes or benefits by anyone
# without specific, additional permission by the owner of the code.
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


