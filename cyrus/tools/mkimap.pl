#!/usr/local/bin/perl5

$imapdconf = shift || "/etc/imapd.conf";
$sievedir = "/usr/sieve";
$nosievedir = 0;
$hashispool = 0;

open CONF, $imapdconf;
print "reading configure file:\n";
while (<CONF>) {
    if (/^#/) { 
	next; 
    }
    print;
    if (/^configdirectory:\s(.*)$/) {
	$conf = $1;
    }
    if (/^sieveuserhomedir:\s(1|t|yes|on)/) {
	$nosievedir = 1;
    }
    if (/^sievedir:\s(.*)$/) {
	$sievedir = $1;
    }
    if (/^partition-.*:\s(.*)$/) {
	if (grep /$1/, @parts) {
	    next;
	}
	push @parts, $1;
    }
    if (/^hashimapspool:\s(1|t|yes|on)/) {
	$hashispool = 1;
	print "i will also hash partitions.\n";
    }
}
print "--- done ---\n";
close CONF;

$d = $conf;

print "creating $d...\n";
mkdir $d, 0755;

chdir $d;
open FOO, ">mailboxes"; close FOO;

mkdir "user", 0755;
foreach $i ("a".."z") { mkdir "user/$i", 0755; }

mkdir "quota", 0755;
foreach $i ("a".."z") { mkdir "quota/$i", 0755; }

mkdir "proc", 0755;
mkdir "log", 0755;
mkdir "msg", 0755;
mkdir "deliverdb", 0755;

# create the sieve stuff
if (!$nosievedir) {
    print "creating $sievedir...\n";

    mkdir $sievedir, 0755;
    chdir $sievedir;
    foreach $i ("a".."z") { mkdir "$i", 0755; }
}

$flag = 0;
while ($part = shift @parts) {
    $flag = 1;

    print "creating $part...\n";
    mkdir $part, 0755;
    chdir $part;
    if ($hashispool) { foreach $i ("a".."z") { mkdir $i, 0755; } }
}

if (!$flag) {
    print "creating /var/spool/imap...\n";
    mkdir "/var/spool/imap", 0755;
    chdir "/var/spool/imap";
    if ($hashispool) { foreach $i ("a".."z") { mkdir $i, 0755; } }
}

print "done\n";

print "\nremember to chown all created directories!\n";
