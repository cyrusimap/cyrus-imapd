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
# $Id: 01-imclient.t,v 1.4.4.1 2003/02/27 18:13:44 rjs3 Exp $
#
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

END {print "not ok 1\n" unless $loaded;}
use Cyrus::IMAP;
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

# create an imclient object
$client = Cyrus::IMAP->new($server);
print "not " if !defined($client);
print "ok 2\n";

# try authenticating as the current user, plaintext
# (tests send in simple mode)
$user = $ENV{USER} || $ENV{LOGNAME} || (getpwuid($<))[0];
system "stty -echo";
print STDERR "Password: ";
chomp($pass = scalar(<STDIN>));
print STDERR "\n";
system "stty echo";
$plen = length($pass);
print "not " if !$client->_send(undef, undef, "LOGIN $user {$plen}\r\n$pass");
$pass = "\0" x length($pass);
$plen = 0;
print "ok 3\n";

# verify it's pointing at the server
$aserver = $client->servername;
print "not " if $aserver ne $server;
print "ok 4\n";

# reauthenticate with the proper method (ugh)
$client = Cyrus::IMAP->new($server);
print "not " if !$client->authenticate('PLAIN');
print "ok 5\n";

# list the authentication methods available (tests send and callbacks)
@caps = ();
$didcap = 0;
sub caps_cb {
  my %cb = @_;
  $didcap = 1;
  push(@caps, map {s/^AUTH=// ? ($_) : ()} split(/ /, $cb{-text}));
}
$client->addcallback({-trigger => 'CAPABILITY', -callback => \&caps_cb});
print "ok 6\n";
$done = 0;
sub done_cb {
  my %cb = @_;
  $ {$cb{-rock}} = 1;
}
$client->send(\&done_cb, \$done, 'CAPABILITY');
$client->processoneevent until $done;
print "not " unless $didcap;
print "ok 7\n";

# if we support kerberos 4 or gssapi auth, log in that way.
foreach $cap (@caps) {
  $client = Cyrus::IMAP->new($server);
  # this is not fatal because someone might not have e.g. Krb5 tickets
  print STDERR "authentication via $cap failed\n"
    if !$client->authenticate($cap);
}
print "ok 8\n";

# more advanced send usage
$client = Cyrus::IMAP->new($server);
print STDERR "enter a different user to authenticate (plaintext) as: ";
chomp($auser = scalar(<STDIN>));
system "stty -echo";
print STDERR "Password: ";
chomp($pass = scalar(<STDIN>));
print STDERR "\n";
system "stty echo";
print "not " if !$client->send(undef, undef, 'LOGIN %a %s', $auser, $pass);
print "ok 9\n";

# authentication with extra parameters
$client = Cyrus::IMAP->new($server);
print "not " if !$client->authenticate(-mechanism => 'PLAIN',
				       -service => 'imap',
				       -user => $auser,
				       -password => $pass,
				       -minssf => 0,
				       -maxssf => 10000);
$pass = "\0" x length($pass);
print "ok 10\n";

BEGIN { $| = 1; print "1..10\n"; }
