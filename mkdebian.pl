#!/usr/bin/perl -w

use strict;
use warnings;

my $num = `git log --pretty=oneline | wc -l`;
chomp($num);

my $branch = `git branch | grep \\\* | cut -c 3-`;
chomp($branch);

my $date = `date -R`;

my $basename = "cyrus-$branch";
my $basedir = $branch eq 'fastmail' ? 'usr/cyrus' : "usr/$basename";

mkdir("debian");
open(FH, ">debian/changelog");
print FH <<EOF;
cyrus-$branch ($num-1) experimental; urgency=low

  * basic package set up

 -- Bron Gondwana <brong\@fastmail.fm>  $date
EOF
close(FH);

open(FH, ">debian/control");
print FH <<EOF;
Source: $basename
Section: mail
Priority: extra
Maintainer: Bron Gondwana <brong\@fastmail.fm>
Build-Depends: libssl-dev, zlib1g-dev, comerr-dev, libsasl2-dev,
	libzephyr-dev, libpcre3-dev, autoconf,
	flex, bison, debhelper, libsnmp-dev

Package: $basename
Architecture: all
Depends: \${shlibs:Depends}
Description: Cyrus package for branch $branch at FastMail.FM

Package: $basename-build
Architecture: all
Depends: \${shlibs:Depends}
Description: Cyrus package for branch $branch at FastMail.FM - build files
EOF
close(FH);

open(FH, ">debian/copyright");
print FH "See the upstream files at CMU\n";
close(FH);

open(FH, ">debian/rules");
print FH <<EOF;
#!/usr/bin/make -f
# debian/rules for alien

# Uncomment this to turn on verbose mode.
#export DH_VERBOSE=1

# Use v4 compatability mode, so ldconfig gets added to maint scripts.
export DH_COMPAT=4

PACKAGE=\$(shell dh_listpackages)

build:
	dh_testdir
	autoreconf -v -i
	./configure --without-krb --with-perl=/usr/bin/perl --enable-idled --with-idle=idled --with-extraident=git-$branch-$num --prefix=/$basedir -with-cyrus-prefix=/$basedir --with-zlib --without-snmp --enable-replication --without-bdb
	make -j 8 all CFLAGS="-g -fPIC -W -Wall -fstack-protector-all"
	make sieve/test
	touch build

clean:
	dh_testdir
	dh_testroot
	dh_clean -d
	rm -f build

binary-indep: build

binary-arch: build
	dh_testdir
	dh_testroot
	dh_clean -k -d
	dh_installdirs

	dh_installdocs
	dh_installchangelogs

	make install DESTDIR=\$(CURDIR)/debian/$basename
	/bin/bash ./libtool --mode=install install -o root -m 755 sieve/test \$(PWD)/debian/$basename/$basedir/bin/sieve-test
	install -o root -m 755 tools/rehash debian/$basename/$basedir/bin/rehash
	install -o root -m 755 tools/mkimap debian/$basename/$basedir/bin/mkimap
	install -o root -m 755 tools/translatesieve debian/$basename/$basedir/bin/translatesieve
	install -o root -m 755 tools/upgradesieve debian/$basename/$basedir/bin/upgradesieve

	# set up source package
	# no need to actually install the built object files!  It's just the source we want
	mkdir -p debian/$basename-build/usr/src/$basename-build/cyrus
	find . -maxdepth 1 -mindepth 1 -not -name debian -not -name .git -print0 | \\
		xargs -0 -r -i cp -a {} debian/$basename-build/usr/src/$basename-build/cyrus/
	
	dh_compress
	dh_makeshlibs
	dh_installdeb
	#-dh_shlibdeps
	dh_gencontrol
	dh_md5sums
	dh_builddeb -- -z3

binary: binary-arch
EOF
close(FH);

chmod(0755, "debian/rules");

print "Debian build environment for branch \"$branch\" set up 

  - run dpkg-buildpackage to build\n";
