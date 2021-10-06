#!/usr/bin/env perl

use strict;
use warnings;

my $mboxlist = "/var/lib/imap/mboxlist.txt";
my $squatlist = "/var/lib/imap/squatlist.txt";
my $tempfile = "/var/lib/imap/squatlist.tmp";
my $stopfile = "/var/lib/imap/squat.stop";
my $adminstopfile = "/var/lib/imap/squat.adminstop";
my $squatlist_lines = 0;
my $mboxlist_lines = 0;
my $line_number = 0;
my $rest = 0;
my $current = "";
my $current_box = "";
my $first_iteration = 1;

my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime(time);

die "$0 administratively stopped" if -e $adminstopfile;

if (-e $stopfile) {
        unlink $stopfile or die "Couldn't unlink $stopfile\n";
        # die "$0: STOPPING";
}

die "$0: Intervention required - temp file exists" if -e $tempfile;

system ("/usr/libexec/cyrus/ctl_mboxlist -d | /bin/cut -f1 > $mboxlist");
die "$0: Mailbox list doesn't seem OK" unless -r $mboxlist && -s $mboxlist;

sub count_lines ($) {

        my $count = 0;

        open (TEMP, shift(@_)) or die "$!";
        while (<TEMP>) {
                $count++;
        }
        close TEMP;

        return $count;
}


if (-e $squatlist) {
        $squatlist_lines = count_lines($squatlist);
        # print "SQ: $squatlist_lines\n";
        $mboxlist_lines = count_lines($mboxlist);
        # print "MB: $mboxlist_lines\n";
        if ($squatlist_lines < $mboxlist_lines) {
                system ("/bin/cat $mboxlist >> $squatlist");
        }
}
else {
        system ("/bin/cp $mboxlist $squatlist");
}

system ("/bin/cp $squatlist $tempfile");

$squatlist_lines = count_lines($squatlist); # aktueller Wert!
# print "SQ: $squatlist_lines\n";

open (SQUAT, $squatlist) or die "$!";

while (<SQUAT>) {
        if (-e $stopfile) {
                close SQUAT;
                ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime(time);
                printf "Ende mit $current am $mday.$mon. um %.2d:%.2d\n", $hour, $min;
                open (CMD, "/bin/grep -n $current $squatlist|/bin/cut -d: -f1|") or die "$!";
                $line_number = <CMD>;
                chomp $line_number;
                # print "Line: $line_number\n";
                close CMD;
                $rest = $squatlist_lines - $line_number;
                # print "Rest: $rest\n";
                system ("/usr/bin/tail -$rest $squatlist > $tempfile");
                system ("/bin/mv $tempfile $squatlist");
                unlink $stopfile or die "Couldn't unlink $stopfile";
                exit 0;
        }
        chomp;
        if ($first_iteration) {
                printf "Beginne mit $_ am $mday.$mon. um %.2d:%.2d\n", $hour, $min;
                $first_iteration = 0;
        }
        $current_box = $_;
        $current_box =~ tr/\./\//;
        system ("/usr/libexec/cyrus/squatter $current_box");
        # print "Current: $current_box\n";
        $current = $_;
        # sleep 1;
}

close SQUAT;
unlink $tempfile or die "Couldn't unlink $tempfile";
unlink $squatlist or die "Couldn't unlink $squatlist";
exit 0;

