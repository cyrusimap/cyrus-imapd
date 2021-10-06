#!/usr/bin/env perl

# Create a workload against a murder frontend
# that will give the MUPDATE server a workout.
#
# Interesting things to add:
#
#   - Try against more than one host to ensure the right thing happens
#     between hosts.
#   - Actually check result codes!!!

$|++;

$host = $ARGV[0] || "sourcefour";

open OUT, "|imtest $host" || die "no imtest";
print OUT "a SELECT INBOX\n";

for($i=0; $i < 1000; $i++) {
  print OUT "b$i CREATE INBOX.foo\n";
  print OUT "c$i SETACL INBOX.foo rjs3.admin lrswipcda\n";
  print OUT "d$i RENAME INBOX.foo INBOX.bar\n";
  print OUT "e$i SETACL INBOX.bar rjs3.admin \"\"\n";
  print OUT "f$i DELETE INBOX.bar\n";

  sleep 1 unless($i % 20);
}

print OUT "g LOGOUT\n";

close(OUT);
