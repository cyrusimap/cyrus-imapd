#!/usr/local/bin/perl5 

#Tim Martin
# 2/10/2000



use Getopt::Long;

$ret = GetOptions("snmp:s","infile:s");

if ($ret == false) { die "Options: -a snmp_file -b c_infile"; }

open (INPUT,"<$opt_snmp");

my $line = 0;
my $found = 0;
my $base = "NOT";
my $num_cmds = 0;

my @list;

#first find the BASE
while( <INPUT> )
{
  chop;
  $line++;

  if (/#.*/)
  {
    #comment line. ignore
  } elsif (/BASE\s+((\d|\.)+)\s*/) {
    #BASE followed by oid
    $base = $1;

  } elsif (/(I)\s*\,\s*(\w+)\s*,\s*(\".*\")\s*\,\s*(\w+)\s*/) {
    #entry
    push(@type_list,$1);
    push(@name_list,$2);
    push(@desc_list,$3);
    push(@how_list,$4);
    
    $num_cmds++;

  } elsif (/\s*/){
    #just whitespace. ignore
  } else {
    die "Syntax error at line $line\n";
  }
}

my $enum_str = "typedef enum {\n";
foreach $a (@name_list)
  {
    $enum_str.="    $a,\n";
  }
substr($enum_str,-2);
$enum_str.="} pushstats_t;\n\n";

my $desc = "static char pushstats_names[$num_cmds][50] = {\n";
foreach $a (@desc_list)
  {
    $desc.="    {$a},\n";
  }
substr($desc,-3);
$desc.="};\n\n";

my $oid = 0;

my $snmp = "static char* pushstats_getoid(pushstats_t cmd)\n{\n";
   $snmp.= "  switch(cmd)\n  {\n";
foreach $a (@name_list)
  {
    $snmp.="    case $a: return \"$base.$oid\";\n";
    $oid++;
  }

   $snmp.= "    default: return \"0.0.0\";\n";
   $snmp.= "  }\n";
   $snmp.= "}\n";


$header_top = " \
/* pushstats.h -- statistics push interface                                  \
                                                                             \
 # Copyright 1998 Carnegie Mellon University                                 \
 #                                                                           \
 # No warranties, either expressed or implied, are made regarding the        \
 # operation, use, or results of the software.                               \
 #                                                                           \
 # Permission to use, copy, modify and distribute this software and its      \
 # documentation is hereby granted for non-commercial purposes only          \
 # provided that this copyright notice appears in all copies and in          \
 # supporting documentation.                                                 \
 #                                                                           \
 # Permission is also granted to Internet Service Providers and others       \
 # entities to use the software for internal purposes.                       \
 #                                                                           \
 # The distribution, modification or sale of a product which uses or is      \
 # based on the software, in whole or in part, for commercial purposes or    \
 # benefits requires specific, additional permission from:                   \
 #                                                                           \
 #  Office of Technology Transfer                                            \
 #  Carnegie Mellon University            \
 #  5000 Forbes Avenue                    \
 #  Pittsburgh, PA  15213-3890            \
 #  (412) 268-4387, fax: (412) 268-7395   \
 #  tech-transfer\@andrew.cmu.edu          \
 *                                        \
 */                                       \
                                          \
#ifndef PUSHSTATS_H                       \
#define PUSHSTATS_H\n\n";

$header_bottom = " \
int pushstats_connect(void);        \
                                    \
int pushstats_close(void);          \
                                    \
int pushstats_log(pushstats_t cmd); \
                                    \
#define PUSHSTATS_MAXCMDS $num_cmds        \
char* pushstats_getname(pushstats_t cmd); \
 \
static char* pushstats_getoid(pushstats_t cmd); \
 \
 \
#endif /* PUSHSTATS_H */ \
";


open (OUTPUT_H,">pushstats.h");

print OUTPUT_H "$header_top\n $enum_str\n $header_bottom\n";

close (OUTPUT_H);

open (OUTPUT_C,">pushstats.c");

print OUTPUT_C "#include \"pushstats.h\"\n\n";
print OUTPUT_C "$snmp\n$desc\n\n";

open (INPUT_IN,"<$opt_infile");

while( <INPUT_IN> )
  {
    print OUTPUT_C $_;
  }

