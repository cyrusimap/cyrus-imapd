#!/usr/local/bin/perl

%data = ();

while(<>) {
    /^(.*) (\d+)$/;
    $data{$1} = $2;
}

$rank = 1;

foreach $key (sort { $data{$b} <=> $data{$a} } (sort keys %data)) {
    print $rank++ . ": $key - $data{$key}\n";
}
