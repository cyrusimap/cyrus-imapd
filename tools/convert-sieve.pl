#!/usr/local/bin/perl

#
# Run this script in your sievedir to fix the names of people's sieve
# directories to conform with the altnamespace format.
# 

$|++;

foreach $file (glob "?/*.*") {
    print "Converting $file...";

    $oldfile = $file;
    $file =~ s/\./^/g;

    print "to $file...";

    if (rename $oldfile, $file) {
	print "Done.\n";
    } else {
	print "Error: $!\n";
    }
}
