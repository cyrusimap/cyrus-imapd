#!/usr/local/bin/perl5
# script to downgrade from cyrus imapd 1.6.2+ to earlier.
# this is a very expensive script and also COPIES data
# so it is extremely slow; it can be rewritten to speed it up immensely
# do NOT run this script while imapd's are running

$| = 1;

$imapdconf = shift || "/etc/imapd.conf";
$hashispool = 0;

open CONF, $imapdconf;
while (<CONF>) {
    print;
    if (/^configdirectory:\s(.*)$/) {
	$conf = $1;
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
close CONF;

print "downgrading configuration directory $conf...";
chdir $conf or die "couldn't change to $conf";

# *** user subdirectory; holds subscription files
print "user ";
chdir "user" or die "couldn't change to user subdir";
foreach $i ("a".."z") { 
    opendir SUB, $i;
    while ($s = readdir SUB) {
	if ($s =~ /^\./s) { next; }
	rename("$i/$s", "$s") or die "couldn't move $s back!";
    }
    closedir SUB;
    rmdir "$i" or die "couldn't remove $i";
}
chdir "..";

# *** quota subdirectory; holds quota files for each quotaroot
print "quota ";
chdir "quota" or die "couldn't change to quota subdir";

# first, create directories we know can't conflict with existing files
foreach $i ("a".."z") {
    rename ($i, ".$i") or die "couldn't rename $i to .$i";
    opendir SUB, ".$i";
    while ($s = readdir SUB) {
	if ($s =~ /^\./s) { next; }
	rename(".$i/$s", $s) or die "couldn't move $s back!";
    }
    closedir SUB;
    rmdir ".$i" or die "couldn't remove .$i";
}
chdir "..";

print "done\n";

# *** now for each data partition
while ($hashispool && ($part = shift @parts)) {
    print "downgrading data partition $part...";
    chdir $part or die "couldn't chdir to $part";
    
    foreach $i ("a".."z") {
	rename ("$i", ".$i") or die "couldn't rename $i to .$i";
    }

    # process each subdir
    foreach $i ("a".."z") {
	print "$i ";
	$i = "." . $i;

	system ("cd $i ; tar cf - . | ( cd .. ; tar xf - )");
	system ("rm -r $i");
    }
    
    print "done\n";
}
