#!/usr/local/bin/perl -w
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

use Cyrus::SIEVE::managesieve;
use Getopt::Long;
use strict;

my $username = "";
my $authname = "";
my $realm = "";
my $ex = "";
my $ret = GetOptions("a|authname:s" => \$authname,
                  "u|username:s" => \$username,
		  "r|realm:s" => \$realm,
		  "e|exec:s" => \$ex
                  );
if (!$ret || $#ARGV != 0) { 
    show_help();
    exit;
}

my $acapserver = $ARGV[0];

my $filehandle;
my $interactive;

if (! $ex eq "") {
    my $tmpfile = "/tmp/sieveshell.tmp";
    open (TMP,">$tmpfile") || die "Unable to open tmp file";
    print TMP $ex;
    close(TMP);
    open (TMP,"<$tmpfile") || die "Unable to open tmp file";
    unlink($tmpfile);
    $filehandle = *TMP;
    $interactive = 0;
} else {
    $filehandle = *STDIN;
    $interactive = 1;
}



sub list_cb {

  my($name, $isactive) = @_ ;
  
  print "$name ";
  if ($isactive == 1) {
    print " <- active script\n";
  } else {
    print "\n";
  }

}

sub prompt {

  my($type, $prompt) = @_ ;

  if (($type eq "username") && (defined $username)) {
      return $username;
  } elsif (($type eq "authname") && (defined $authname)) {
      return $authname;
  } elsif (($type eq "realm") && (defined $realm)) {
      return $realm;
  }

  print "$prompt: ";

  $b = <STDIN>;
  chop($b);
  
  return $b;
}

sub show_help {
  print "Usage:\n";
  print "  sieveshell [-u username] [-a authname] [-r realm] <server>\n";
  print "\n";
  print "help             - this screen\n";
  print "list             - list scripts on server\n";
  print "put <filename>   - upload script to server (implicitly set active if no active script)\n";
  print "get <name> [<filename>] - get script. if no filename display to stdout\n";
  print "delete <name>    - delete script.\n";
  print "activate <name>  - set a script as the active script\n";
  print "quit             - Quit\n";
}

# main code

print "connecting to $acapserver\n";

my $obj = sieve_get_handle($acapserver,
			   "prompt", "prompt", "prompt", "prompt");

if (!defined $obj) {
    my $err = sieve_get_global_error();
    die "unable to connect to server: $err";
}

print "> " if ($interactive);

while(<$filehandle>) {
    my @words = split ' ',$_;
    my $str;
    if ($#words < 0) {
	print "> " if ($interactive);
	next;
    }

    if (($words[0] eq "put") || 
	($words[0] eq "p")) {
	$ret = sieve_put_file($obj, $words[1]);
	if ($ret != 0) { 
	    my $errstr = sieve_get_error($obj);
	    print "upload failed: $errstr\n"; 
	}
    } elsif (($words[0] eq "list") || 
	     ($words[0] eq "l") || 
	     ($words[0] eq "ls")) {
	$ret = sieve_list($obj, "list_cb");
	if ($ret != 0) { 
	    my $errstr = sieve_get_error($obj);
	    print "list failed: $errstr\n";
	}
    } elsif (($words[0] eq "activate") || 
	     ($words[0] eq "a")) {
	$ret = sieve_activate($obj, $words[1]);
	if ($ret != 0) { 
	    my $errstr = sieve_get_error($obj);
	    print "activate failed: $errstr\n";
	}
    } elsif (($words[0] eq "delete") || 
	     ($words[0] eq "d")) {    
	$ret = sieve_delete($obj, $words[1]);
	if ($ret != 0) { 
	    my $errstr = sieve_get_error($obj);
	    print "delete failed: $errstr\n"; 
	}
    } elsif (($words[0] eq "get") || 
	     ($words[0] eq "g")) {
	$str = "";
	$ret = sieve_get($obj, $words[1], $str);
	if ($ret != 0) { 
	    my $errstr = sieve_get_error($obj);
	    print "get failed: $errstr\n"; 
	} else {
	    if ($words[2]) {
		open (OUTPUT,">$words[2]") || die "Unable to open $words[2]";
		print OUTPUT $str;
		close(OUTPUT);
	    } else {
		print $str;
	    }
	}
    } elsif (($words[0] eq "quit") || ($words[0] eq "q")) {
	exit 0;
    } elsif (($words[0] eq "help") || ($words[0] eq "?")) {
	show_help();
    } else {
	print "Invalid command: $words[0]\n";
    } 
    
    print "> " if ($interactive);
}
