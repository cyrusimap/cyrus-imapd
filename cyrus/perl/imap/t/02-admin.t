# 
# Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer. 
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any other legal
#    details, please contact  
#      Office of Technology Transfer
#      Carnegie Mellon University
#      5000 Forbes Avenue
#      Pittsburgh, PA  15213-3890
#      (412) 268-4387, fax: (412) 268-7395
#      tech-transfer@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# $Id: 02-admin.t,v 1.4.4.1 2003/02/27 18:13:44 rjs3 Exp $
#
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

END {print "not ok 1\n" unless $loaded;}
use Cyrus::IMAP::Admin;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# find a server
$old = select(STDERR); $| = 1; select($old);
$server = $ENV{IMAPSERVER} || $ENV{BATISERVER};
while (!defined($server) || $server eq '') {
  print STDERR "enter an IMAP server to use for testing: ";
  chomp($server = scalar(<STDIN>));
  # needed so ->servername test will work; imclient does this internally
  $server = (gethostbyname($server))[0];
}

# somewhat lame test of Cyrus::IMAP::Admin; can't really test it without
# test accounts and maybe even a test server...

print "not " unless defined ($client = Cyrus::IMAP::Admin->new($server));
print "ok 2\n";
print "not " unless $client->authenticate;
print "ok 3\n";
@mb = $client->list('INBOX', '*');
print "not " unless @mb;
foreach (@mb) {
  print STDERR "> $_->[0] ($_->[1])\n";
}
print "ok 4\n";

# list ACL on INBOX
print "not " unless %acl = $client->listacl('INBOX');
foreach (keys %acl) {
  print STDERR ">> $_: $acl{$_}\n";
}
print "ok 5\n";

# quota and quotaroot
print "not " unless defined ($qroot = $client->quotaroot('INBOX'));
print "ok 6\n";
print "not " if !defined (@quota = $client->quota($qroot));
print "ok 7\n";

BEGIN { $| = 1; print "1..7\n"; }
