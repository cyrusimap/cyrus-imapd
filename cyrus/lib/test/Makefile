.c.o:
	gcc -I.. -c $<

testglob: testglob.o ../libcyrus.a
	gcc -o testglob testglob.o ../libcyrus.a ../libcyrus_min.a -ldb-4.0

imapurl: imapurl.o ../libcyrus.a
	gcc -o imapurl imapurl.o ../libcyrus.a ../libcyrus_min.a

all: testglob imapurl
