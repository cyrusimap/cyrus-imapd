#!/usr/local/bin/perl -w

# test-imsp.pl
#
# Joseph Jackson
# 09-May-2000
#
# Quick demonstration and test for the Cyrus IMSP Perl module.

use Cyrus::IMAP::IMSP;

print "Logging in...\n";
$server = $ARGV[0] || 'imsp.andrew.cmu.edu';
my $client = Cyrus::IMAP::IMSP->new($server, $ARGV[1] || "imsp");
die "New command failed" if (!defined $client);

#
# The maxssf=0 option is required. 
# Taking it away can lead to hangs in the send function.
#
#
# Use this form if you are an IMSP admin who can act on behalf of others
# $rc = $client->authenticate(-maxssf => 0, -user => 'pcyrus');
#
$client->authenticate(-maxssf => 0);
print "Error from authenticate is: ", $client->error if ($client->error);

print "Getting common.* options\n";
%options = $client->get('common.*');
print "Error from get is: ", $client->error, "\n" if ($client->error);
foreach my $option (sort keys %options) {
  print "  Option: '", $option, "'\n  Value:  '", $options{$option}, "'\n";
}

print "Setting testing.* options\n";
print "  testing.one... ";
if (!$client->set('testing.one', 'string value')) {
  print "Error from set is: ", $client->error;
}
print "\n";
print "  testing.two... ";
if (!$client->set('testing.two', '2')) {
  print "Error from set is: ", $client->error;
}
print "\n";
print "  testing.empty... ";
if (!$client->set('testing.empty', '')) {
  print "Error from set is: ", $client->error;
}
print "\n";
print "  testing.deleteme... ";
if (!$client->set('testing.deleteme', 'delete this one')) {
  print "Error from set is: ", $client->error;
}
print "\n";
print "  testing.complicated... ";
if (!$client->set('testing.complicated',
	  '(("Cyrus:INBOX" ((1024 768 0 0 300 400)) (true false)))')) {
  print "Error from set is: ", $client->error;
}
print "\n";
print "  testing.embeddedcr... ";
if (!$client->set('testing.embeddedcr',
	  "There is a CR LF here:\r\nHere's another:\r\nThat was it!")) {
  print "Error from set is: ", $client->error;
}
print "\n";

print "Getting testing options\n";
%options = $client->get('testing.*');
print "Error from get is: ", $client->error, "\n" if ($client->error);
foreach my $option (sort keys %options) {
  print "  Option: '", $option, "'\n  Value:  '", $options{$option}, "'\n";
}

print "Unsetting testing.deleteme and testing.not-there\n";
if (!$client->unset('testing.deleteme')) {
  print "Error from unset is: ", $client->error, "\n";
}
if (!$client->unset('testing.not-there')) {
  print "EXPECTED Error from unset is: ", $client->error, "\n";
}

print "Getting testing options\n";
%options = $client->get('testing.*');
print "Error from get is: ", $client->error, "\n" if ($client->error);
foreach my $option (sort keys %options) {
  print "  Option: '", $option, "'\n  Value:  '", $options{$option}, "'\n";
}

print "Unsetting remaining testing options\n";
if (!$client->unset('testing.one')) {
  print "Error from unset is: ", $client->error, "\n";
}
if (!$client->unset('testing.two')) {
  print "Error from unset is: ", $client->error, "\n";
}
if (!$client->unset('testing.empty')) {
  print "Error from unset is: ", $client->error, "\n";
}
if (!$client->unset('testing.complicated')) {
  print "Error from unset is: ", $client->error, "\n";
}
if (!$client->unset('testing.embeddedcr')) {
  print "Error from unset is: ", $client->error, "\n";
}

# Should return nothing
print "Verifying that all the options are gone\n";
%options = $client->get('testing.*');
print "Error from get is: ", $client->error, "\n" if ($client->error);
foreach my $option (sort keys %options) {
  print "  Option: '", $option, "'\n  Value:  '", $options{$option}, "'\n";
}
