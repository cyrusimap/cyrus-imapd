#!/usr/local/bin/perl

$prefix = "test.mupdate-load.";
$lups = 150;
$lookups = 10;

srand(time());
@thelist = ();

for($i=0; $i<=$lups; $i++) {
  push @thelist, $prefix . $$ . ".$i";
}

$tag = 0;

foreach $item (@thelist) {
	print $tag++ . " RESERVE \"" . $item . "\" \"borked.andrew.cmu.edu\"\r\n";
	$todo = int(rand $lookups) + 1;
	for($i=1; $i<$todo; $i++) {
	    print $tag++ . " FIND \"" . $thelist[int(rand scalar @thelist)] . "\"\r\n";
	}
}

foreach $item (@thelist) {
	print $tag++ . " DELETE \"" . $item . "\"\r\n";
}

