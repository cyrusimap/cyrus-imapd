#!/usr/bin/env perl

#
# This script takes the output of arbitron (run without the -o option)
# and prints out first
# a ranking of mailboxes by # of people who selected the mailbox
# and then a ranking of mailbox by # of subscribers.
#

%data = ();
%subs = ();

while(<>) {
    /^(.*) (\d+) (\d+)$/;
    $data{$1} = $2;
    $subs{$1} = $3;
}

$rank = 1;

foreach $key (sort { $data{$b} <=> $data{$a} } (sort keys %data)) {
    print $rank++ . ": $key - $data{$key}\n";
}

print "\n\n";

$rank = 1;

foreach $key (sort { $subs{$b} <=> $subs{$a} } (sort keys %subs)) {
    print $rank++ . ": $key - $subs{$key}\n";
}

