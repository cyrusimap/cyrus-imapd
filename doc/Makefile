# Makefile for cyrus documentation directory
# 
# Copyright 1998 Carnegie Mellon University
# 
# No warranties, either expressed or implied, are made regarding the
# operation, use, or results of the software.
#
# Permission to use, copy, modify and distribute this software and its
# documentation is hereby granted for non-commercial purposes only
# provided that this copyright notice appears in all copies and in
# supporting documentation.
#
# Permission is also granted to Internet Service Providers and others
# entities to use the software for internal purposes.
#
# The distribution, modification or sale of a product which uses or is
# based on the software, in whole or in part, for commercial purposes or
# benefits requires specific, additional permission from:
#
#  Office of Technology Transfer
#  Carnegie Mellon University
#  5000 Forbes Avenue
#  Pittsburgh, PA  15213-3890
#  (412) 268-4387, fax: (412) 268-7395
#  tech-transfer@andrew.cmu.edu
# 

all: htmlstrip docs clean

DOCS= README install overview changes bugs

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

bugs: html/bugs.html htmlstrip
	./htmlstrip html/bugs.html > bugs

clean:
	rm -f *.o *~ Makefile.bak htmlstrip

realclean: clean
	rm -f $(DOCS)

distclean: clean

depend:

# DO NOT DELETE THIS LINE -- make depend depends on it.


