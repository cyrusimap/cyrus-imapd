# cyrinit.c -- Cyrus administrative client initialization for interactive mode
# $Id: cyrinit.tcl,v 1.16 2000/01/28 22:09:40 leg Exp $
# Copyright 1998 Carnegie Mellon University
# 
# No warranties, either expressed or implied, are made regarding the
# operation, use, or results of the software.
#
# Permission to use, copy, modify and distribute this software and its
# documentation is hereby granted for non-commercial purposes only
# provided that this copyright notice appears in all copies and in
# supporting documentation.
#
# Permission is also granted to Internet Service Providers and others
# entities to use the software for internal purposes.
#
# The distribution, modification or sale of a product which uses or is
# based on the software, in whole or in part, for commercial purposes or
# benefits requires specific, additional permission from:
#
#  Office of Technology Transfer
#  Carnegie Mellon University
#  5000 Forbes Avenue
#  Pittsburgh, PA  15213-3890
#  (412) 268-4387, fax: (412) 268-7395
#  tech-transfer@andrew.cmu.edu
#
#

# Parse args
set i 0;
set help 0;
set conn_args ""
set auth_args ""
while {$i < $argc} {
    switch -exact -- [lindex $argv $i] {
	- {}
	-- {}
	-u {incr i; lappend auth_args -user [lindex $argv $i] }
	-user {incr i; lappend auth_args -user [lindex $argv $i] }
	-l {incr i; lappend auth_args -layers [lindex $argv $i] }
	-layers {incr i; lappend auth_args -layers [lindex $argv $i] }
	-m {incr i; lappend auth_args -mech [lindex $argv $i] }
	-mech {incr i; lappend auth_args -mech [lindex $argv $i] }
	-notls { lappend auth_args -notls  }
	-tlskey {incr i; lappend auth_args -tlskey [lindex $argv $i] }
	-h {incr i; set help 1 }
	-help {incr i; set help 1 }
	default {lappend conn_args [lindex $argv $i]}
    }
    incr i
}
unset i

# Connect to server
if {[llength $conn_args] == 0 || $help == 1} {
    if {$tcl_interactive != 0} {
        puts "usage: $argv0 \[-user user] \[-layers 0,1,56,...] \[-mech mech] server \[port]"
        exit 1
    } else {
        error "usage: $argv0 \[-user user] \[-layers #] \[-mech mech] server \[port]"
    }
}
eval cyradm connect cyr_conn $conn_args
unset conn_args
unset help

# Authenticate, prompting for userid and password as necessary
eval cyr_conn authenticate $auth_args
unset auth_args

# Initialize default mailbox and prompt
set cyr_mailbox inbox
set tcl_prompt1 {
    puts -nonewline stdout "[cyr_conn servername]> "
#    stty echo
}

# createmailbox command
#
set cyr_help(createmailbox) "createmailbox, cm\tcreate a mailbox"
set cyr_alias(cm) createmailbox
set cyr_usage(createmailbox) {MAILBOX [PARTITION]}
set body {
    global cyr_conn
    global cyr_mailbox
    if {![string compare $mailbox .]} {set mailbox $cyr_mailbox}
    if {[string length $partition]} {
	cyr_conn createmailbox $mailbox $partition
    } else {
	cyr_conn createmailbox $mailbox
    }
    set cyr_mailbox $mailbox
    return
}
proc createmailbox {mailbox {partition {}}} $body
proc cm {mailbox {partition {}}} $body

# deletemailbox command
#
set cyr_help(deletemailbox) "deletemailbox, dm\tdelete a mailbox"
set cyr_alias(dm) deletemailbox
set cyr_usage(deletemailbox) {MAILBOX [HOSTNAME]}
set body {
    global cyr_conn
    global cyr_mailbox
    if {![string compare $mailbox .]} {set mailbox $cyr_mailbox}
    if {[string length $hostname]} {
	cyr_conn deletemailbox $mailbox $hostname
    } else {
	cyr_conn deletemailbox $mailbox
    }
    set cyr_mailbox $mailbox
    return
}
proc deletemailbox {mailbox {hostname {}}} $body
proc dm {mailbox {hostname {}}} $body

# renamemailbox command
#
set cyr_help(renamemailbox) "renamemailbox, renm\trename a mailbox"
set cyr_alias(renm) renamemailbox
set cyr_usage(renamemailbox) {MAILBOX NEWMAILBOX [PARTITION]}
set body {
    global cyr_conn
    global cyr_mailbox
    if {![string compare $mailbox .]} {set mailbox $cyr_mailbox}
    if {[string length $partition]} {
	cyr_conn renamemailbox $mailbox $newmailbox $partition
    } else {
	cyr_conn renamemailbox $mailbox $newmailbox
    }
    set cyr_mailbox $newmailbox
    return
}
proc renamemailbox {mailbox newmailbox {partition {}}} $body
proc renm {mailbox newmailbox {partition {}}} $body

# listmailbox command
#
set cyr_help(listmailbox) "listmailbox, lm\t\tlist mailboxes"
set cyr_alias(lm) listmailbox
set cyr_usage(listmailbox) {[-s[ubscribed]] PATTERN [REFERENCE]}
set body {
    global cyr_conn
    set i 0
    set len [llength $args]

    while {$i < $len} {
	set switch [lindex $args $i]
	if {![string match -* $switch]} break
	if {[string match -- $switch]} {
	    incr i
	    break
	}
	if {[string match -s $switch]} {
	    set args [lreplace $args $i $i -subscribed]
	} elseif {![string match -subscribed $switch]} {
	    error "unrecognized switch"
	}
	incr i
    }

    if {$i == $len} {
	lappend args "*"
	incr len
    }
    if {$i + 1 > $len} {
	error "too many arguments"
    }

    set rawlist [eval cyr_conn listmailbox $args]
    
    if {[llength $rawlist] == 0} return

    set maxlen 0
    foreach mailbox $rawlist {
	if {[lsearch -regexp [lindex $mailbox 1] {\\[Nn][Oo][Ss][Ee][Ll][Ee][Cc][Tt]}] >= 0} {
	    set mailbox "([lindex $mailbox 0])"
	} elseif {[lsearch -regexp [lindex $mailbox 1] {\\[Mm][Aa][Rr][Kk][Ee][Dd]}] >= 0} {
	    set mailbox "[lindex $mailbox 0] *"
	} else {
	    set mailbox [lindex $mailbox 0]
	}
	if {$maxlen < [string length $mailbox]} {
	    set maxlen [string length $mailbox]
	}
	lappend newlist $mailbox
    }

    set written 0
    incr maxlen 2
    set columns [expr 80/$maxlen]
    if {$columns < 1} {set columns 1}
    set newlistlen [llength $newlist]
    set rows [expr ($newlistlen+$columns-1)/$columns]
    for {set i 0} {$i < $rows} {incr i} {
	for {set j 0} {$j*$rows < $newlistlen} {incr j} {
	    if {$j > 0} {
	    	append result [string range \
			"                                        " 0 $lastpad]
	    }
	    set mailbox [lindex $newlist [expr $i+$j*$rows]]
	    append result $mailbox
	    set lastpad [expr $maxlen - [string length $mailbox] - 1]
	}
	append result "\n"
    }
    return $result
}
proc listmailbox {args} $body
proc lm {args} $body

# setaclmailbox command
#
set cyr_help(setaclmailbox) "setaclmailbox, sam\tset an ACL on a mailbox"
set cyr_alias(sam) setaclmailbox
set cyr_usage(setaclmailbox) {MAILBOX IDENTIFIER RIGHTS [IDENTIFIER RIGHTS]...}
set body {
    global cyr_conn
    global cyr_mailbox

    set arglen [llength $args]
    if {$arglen < 3 || $arglen%2 != 1} {
	error "wrong number arguments"
    }

    if {![string compare [lindex $args 0] .]} {
	set args [lreplace $args 0 0 $cyr_mailbox]
    }

    eval cyr_conn setaclmailbox $args

    set $cyr_mailbox [lindex $args 0]
    return
}
proc setaclmailbox {args} $body
proc sam {args} $body

# deleteaclmailbox command
#
set cyr_help(deleteaclmailbox) "deleteaclmailbox, dam\tdelete an ACL on a mailbox"
set cyr_alias(dam) deleteaclmailbox
set cyr_usage(deleteaclmailbox) {MAILBOX IDENTIFIER [IDENTIFIER]...}
set body {
    global cyr_conn
    global cyr_mailbox

    if {[llength $args] < 2} {
	error "too few arguments"
    }

    if {![string compare [lindex $args 0] .]} {
	set args [lreplace $args 0 0 $cyr_mailbox]
    }

    eval cyr_conn deleteaclmailbox $args

    set $cyr_mailbox [lindex $args 0]
    return
}
proc deleteaclmailbox {args} $body
proc dam {args} $body

# listaclmailbox command
#
set cyr_help(listaclmailbox) "listaclmailbox, lam\tlist the ACL on a mailbox"
set cyr_alias(lam) listaclmailbox
set cyr_usage(listaclmailbox) {MAILBOX}
set body {
    global cyr_conn
    global cyr_mailbox
    if {![string compare $mailbox .]} {set mailbox $cyr_mailbox}

    set rawlist [cyr_conn listaclmailbox $mailbox]
    set rawlen [llength $rawlist]

    for {set i 0} {$i < $rawlen} {incr i 2} {
	append result "[lindex $rawlist $i] [lindex $rawlist [expr $i+1]]\n"
    }

    set cyr_mailbox $mailbox
    return $result
}
proc listaclmailbox {mailbox} $body
proc lam {mailbox} $body
    
# setquota command
#
set cyr_help(setquota) "setquota, sq\t\tset quota limits"
set cyr_alias(sq) setquota
set cyr_usage(setquota) {ROOT [none|NUMBER|[RESOURCE NUMBER]...]}
set body {
    global cyr_conn
    global cyr_mailbox

    if {[llength $args] < 2} {
	error "too few arguments"
    }
    if {[llength $args] == 2} {
	switch -regexp -- [lindex $args 1] {
	    none {set args [lreplace $args 1 1]}
	    [0-9]+ {set args [linsert $args 1 STORAGE]}
	    default {error "invalid quota"}
	}
    }

    if {![string compare [lindex $args 0] .]} {
	set args [lreplace $args 0 0 $cyr_mailbox]
    }

    eval cyr_conn setquota $args

    set $cyr_mailbox [lindex $args 0]
    return
}
proc setquota {args} $body
proc sq {args} $body
    
# listquota command
#
set cyr_help(listquota) "listquota, lq\t\tlist quota on root"
set cyr_alias(lq) listquota
set cyr_usage(listquota) {ROOT}
set body {
    global cyr_conn
    global cyr_mailbox
    if {![string compare $root .]} {set root $cyr_mailbox}

    set rawlist [cyr_conn listquota $root]
    set rawlen [llength $rawlist]
    
    for {set i 0} {$i < $rawlen} {incr i 3} {
	set used [lindex $rawlist [expr $i+1]]
	set limit [lindex $rawlist [expr $i+2]]
	if {$limit == 0} {
	    set percent 100
	} else {
	    set percent [expr ($used*100)/$limit]
	}
	append result "[lindex $rawlist $i] $used/$limit ($percent%)\n"
    }
    if {$rawlen == 0} {set result "NO LIMIT"}

    set cyr_mailbox $root
    return $result
}
proc listquota {root} $body
proc lq {root} $body

# listquotaroot command
#
set cyr_help(listquotaroot) "listquotaroot, lqr, lqm\tlist quota roots on mailbox"
set cyr_alias(lqr) listquotaroot
set cyr_alias(lqm) listquotaroot
set cyr_usage(listquotaroot) {MAILBOX}
set body {
    global cyr_conn
    global cyr_mailbox
    if {![string compare $mailbox .]} {set mailbox $cyr_mailbox}

    set rawlist [cyr_conn listquotaroot $mailbox]    
    foreach root $rawlist {
	set rootlen [llength $root]
	append result "[lindex $root 0]"
	for {set i 1} {$i < $rootlen} {incr i 3} {
	    set used [lindex $root [expr $i+1]]
	    set limit [lindex $root [expr $i+2]]
	    if {$limit == 0} {
		set percent 100
	    } else {
		set percent [expr ($used*100)/$limit]
	    }
	    append result " [lindex $root $i] $used/$limit ($percent%)"
	}
	if {$rootlen == 1} {append result " NO LIMIT"}
	append result "\n"
    }
    if {[llength $rawlist] == 0} {set result "NO QUOTA ROOTS"}

    set cyr_mailbox $mailbox
    return $result
}
proc listquotaroot {mailbox} $body
proc lqr {mailbox} $body
proc lqm {mailbox} $body

set cyr_help(quit) "quit\t\t\texit program"
set cyr_usage(quit) {}
proc quit {} {exit}

set cyr_help(help) "help\t\t\tget help on commands"
set cyr_usage(help) {[COMMAND]...}
proc help {args} {
    global cyr_help
    global cyr_alias
    global cyr_usage
    if {[llength $args] == 0} {
	foreach cmd [lsort [array names cyr_help]] {
	    append result $cyr_help($cmd)
	    append result "\n"
	}
    } else {
	foreach cmd $args {
	    if {[catch {set fullcmd $cyr_alias($cmd)}]} {
		set fullcmd $cmd
	    }

	    if {[catch {append result "$cyr_help($fullcmd)\nusage: $cmd $cyr_usage($fullcmd)\n" }]} {
		append result "Unknown command '$cmd'\n"
	    }
	}
    }
    return $result
}


unset body
