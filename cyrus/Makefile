all: do-configure
	(cd cyren; $(MAKE) all)

do-configure: cyren/Makefile.in cyren/ckimail/Makefile.in cyren/xibiff/Makefile.in cyren/configure
	(cd cyren; ./configure --prefix="")

install: 
	(cd cyren; $(MAKE) install)

love:
	@echo "Not war?"
