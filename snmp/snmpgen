#!/usr/local/bin/perl5 -w

#Tim Martin
# 2/10/2000

use Getopt::Long;
my $opt_extra = undef;

$ret = GetOptions("extra:s");
if (!$ret || $#ARGV != 0) { 
    print STDERR "snmpgen [--extra=trailer.in] app.snmp\n";
    exit;
}

$infile = $ARGV[0];

if ($infile =~ m|.*/(.*)\.snmp|) {
    $basename = $1;
} elsif ($infile =~ m|(.*)\.snmp|) {
    $basename = $1;
} else {
    $basename = $infile;
}
print "basename $basename\n";
$outheader = "$basename.h";
$outprog = "$basename.c";

open (INPUT,"<$infile");

my $linenum = 0;
my $found = 0;
my $base = "NOT";
my $num_cmds = 0;

my %T; # maps names to types
my %D; # maps names to descs
my %O; # maps names to oids

my @list;

#first find the BASE
while (defined ($line = <INPUT>)) {
    $linenum++;
    
    if ($line =~ /^#/) {
	# comment
	next;
    }
    if ($line =~ /^\s*$/) {
	# just whitespace. ignore
	next;
    }

    if ($line =~ /^BASE\s+((\d|\.)+)/) {
	$base = $1;
	$basecount = 0;
	next;
    }
    chomp $line;
    ($type, $name, $desc, $oid, $dummy) = split(/\s*,\s*/, $line, 5);

    if (!(defined $oid) || (defined $dummy)) {
	die "syntax error on line $linenum\n";
    }

    if ($oid eq "auto") {
	$oid = $base . ".$basecount";
	$basecount++;
    }

    $T{$name} = $type;
    $D{$name} = $desc;
    $O{$name} = $oid;
}
    
open (OUTPUT_H, ">$outheader");

print OUTPUT_H <<EOF
/* $outheader -- statistics push interface
 * generated automatically from $infile by snmpgen
 *
 * Copyright 2000 Carnegie Mellon University
 *
 * No warranty, yadda yadda
 */                                       
                                          
#ifndef ${basename}_H    
#define ${basename}_H

typedef enum {
EOF
;

foreach my $name (keys %T) {
    print OUTPUT_H "    $name,\n";
}

print OUTPUT_H <<EOF
} ${basename}_t;

int snmp_connect(void);        
                                    
int snmp_close(void);          
                                    
/* only valid on counters */
int snmp_increment(${basename}_t cmd, int);

/* only valid on values */
int snmp_set(${basename}_t cmd, int);
                                    
const char *snmp_getdescription(${basename}_t cmd); 
 
const char *snmp_getoid(${basename}_t cmd); 
 
#endif /* ${basename}_H */ 

EOF
;

close OUTPUT_H;

open (OUTPUT_C,">$outprog");

print OUTPUT_C <<EOF
/* $outprog -- automatically generated from $infile by snmpgen */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#include "$outheader"


const char *snmp_getdescription(${basename}_t evt)
{
    switch (evt) {
EOF
;

foreach my $a (keys %T)
{
    print OUTPUT_C "        case $a: return $D{$a};\n";
}

print OUTPUT_C <<EOF
    }
    return NULL;
}

const char *snmp_getoid(${basename}_t evt)
{
    switch (evt) {
EOF
;

foreach my $a (keys %T)
{
    print OUTPUT_C "        case $a: return \"$O{$a}\";\n";
}


$snmp.= "    default: return \"0.0.0\";\n";
$snmp.= "  }\n";
$snmp.= "}\n";
    
print OUTPUT_C <<EOF
    }
    return NULL;
}

#define SOCK_PATH "/tmp/.snmp_door"

static int mysock = -1;
static struct sockaddr_un remote;


int snmp_connect(void)
{
    int s, len;
    int fdflags;

    if ((s = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
	return 1;
    }

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, SOCK_PATH);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);

    /* put us in non-blocking mode */
    fdflags = fcntl(s, F_GETFD, 0);
    if (fdflags != -1) fdflags = fcntl(s, F_SETFL, O_NONBLOCK | fdflags);
    if (fdflags != -1) { close(s); return -1; }

    mysock = s;

    return 0;
}

int snmp_close(void)
{
    if (mysock > -1)
	close(mysock);

    return 0;
}

int snmp_increment(${basename}_t cmd, int incr)
{
    int len;
    char tosend[100];

    if (mysock == -1) return 1;

    strcpy(tosend, snmp_getoid(cmd));
    strcat(tosend,"\n");

    len = strlen(remote.sun_path) + sizeof(remote.sun_family);

    if (sendto(mysock, tosend, strlen(tosend), 0, (struct sockaddr *) &remote, len) == -1) {
	return 1;
    }

    return 0;
}

int snmp_set(${basename}_t cmd, int value)
{
    fprintf(stderr, "bah humbug\n");
}

EOF
;

if (defined $opt_extra) {
   open (INPUT_IN,"<$opt_extra");
   while( <INPUT_IN> )
   {
       print OUTPUT_C;
   }
   close INPUT_IN;
} 

close OUTPUT_C;
