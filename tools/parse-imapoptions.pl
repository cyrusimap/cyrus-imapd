#!/usr/bin/env perl
use warnings;
use strict;

my %simple = map { $_ => 1 } qw(BYTESIZE DURATION INT SWITCH STRING);
my %multi = map { $_ => 1 } qw(BITFIELD ENUM STRINGLIST);
my $rst = 'docsrc/reference/manpages/configs/imapd.conf.rst';

while (<>) {
    chomp;
    
    my $orig = $_;

    if (m/^(\# )?{ "([\w-]+)", *"?([^,"]*)"?, *([A-Z]+)(.*?) *}$/) {
        my $doc_only = !!$1;
        my $name = $2;
        my $def = $3;
        my $type = $4;
        my $rest = $5;
        my $last_modified;
        my $deprecated_since;
        my $replaced_by;
        my @allowed_values;

        my $fname = "new_imapoptions/$name";

        # skip ones that have already been manually converted
        next if -e $fname;

        if ($simple{$type}) {
            $rest =~ s/^,//;
        }
        elsif ($multi{$type}) {
            if ($rest =~ m/^\(([^\)]*)\), *(.*)$/) {
                my $av = $1;
                $rest = $2;

                (undef, @allowed_values) = split /[", ]+/, $av;
            } 
            else {
                die "couldn't parse $type for $name";
            }
        }
        else { 
            next;
        }

        if (not $rest) {
            print STDERR "orig: $orig\n";
        }
        ($last_modified, $deprecated_since, $replaced_by)
            = split(/, */, $rest);

        open my $fh, '>', $fname or die "$fname: $!";
#         my $fh = *STDOUT;

        print $fh "Name: $name\n";
        print $fh "Type: $type\n";

        if (@allowed_values) {
            print $fh "Allowed-Values: " . join(' ', @allowed_values) . "\n";
        }

        print $fh "Default-Value: $def\n";

        $last_modified =~ s/[" ]//g;
        print $fh "Last-Modified: $last_modified\n";
        print $fh "For-Documentation-Only: 1\n" if $doc_only;

        if ($deprecated_since) {
            $deprecated_since =~ s/[" ]//g;
            print $fh "Deprecated-Since: $deprecated_since\n";
        }
        if ($replaced_by) {
            $replaced_by =~ s/[" ]//g;
            print $fh "Replaced-By: $replaced_by\n";
        }

        my @doc = qx(sed -n '/startblob $name\$/,/endblob $name\$/p' $rst);

        foreach my $line (@doc[3 .. $#doc - 2]) {
            $line =~ s/^    //g;
            print $fh $line;
        }

        close $fh;
    }
}
