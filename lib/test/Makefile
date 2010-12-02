.c.o:
	gcc -I.. -c $<

testglob: testglob.o ../libcyrus.a
	gcc -o testglob testglob.o ../libcyrus.a ../libcyrus_min.a -ldb-4.0

all: testglob
