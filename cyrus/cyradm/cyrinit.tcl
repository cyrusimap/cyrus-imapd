# cyrinit.c -- Cyrus administrative client initialization for interactive mode
#
#	(C) Copyright 1994 by Carnegie Mellon University
#
#                      All Rights Reserved
#
# Permission to use, copy, modify, and distribute this software and its 
# documentation for any purpose and without fee is hereby granted, 
# provided that the above copyright notice appear in all copies and that
# both that copyright notice and this permission notice appear in 
# supporting documentation, and that the name of CMU not be
# used in advertising or publicity pertaining to distribution of the
# software without specific, written prior permission.  
# 
# CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
# ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
# CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
# ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
# ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
# SOFTWARE.
#
#

# Parse args
set i 0;
set conn_args ""
set auth_args ""
while {$i < $argc} {
    switch -exact -- [lindex $argv $i] {
	- {}
	-- {}
	-u {incr i; append auth_args -user [lindex $argv $i]}
	-user {incr i; append auth_args -user [lindex $argv $i]}
	-p {incr i; append auth_args -protection [lindex $argv $i]}
	-protection {incr i; append auth_args -protection [lindex $argv $i]}
	default {append conn_args [lindex $argv $i]}
    }
    incr i
}
unset i

# Connect to server
if {[llength $conn_args] == 0} {
    error "usage: $argv0 \[-user user] \[-protection prot] server \[port]"
}
eval cyradm connect cyr_conn $conn_args
unset conn_args

# Authenticate, prompting for userid and password as necessary
eval cyr_conn authenticate $auth_args -pwcommand {{
    set hostname %h
    if {[string length %u] == 0} {
	puts -nonewline "$hostname userid: "
	gets stdin userid
    } else {set userid %u}
    exec stty -echo >@stdout
    puts -nonewline "$hostname password: "
    gets stdin passwd
    exec stty echo >@stdout
    puts ""
    list $userid $passwd
}   }
unset auth_args

# Initialize default mailbox and prompt
set cyr_mailbox inbox
set tcl_prompt1 {
    puts -nonewline stdout "[cyr_conn servername]> "
}

# createmailbox command
#
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
set body {
    global cyr_conn
    global cyr_mailbox
    if {![string compare $root .]} {set root $cyr_mailbox}

    set rawlist [cyr_conn listquota $root]
    set rawlen [llength $rawlist]
    
    for {set i 0} {$i < $rawlen} {incr i 3} {
	set used [lindex $rawlist [expr $i+1]]
	set limit [lindex $rawlist [expr $i+2]]
	set percent [expr ($used*100)/$limit]
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
	    set percent [expr ($used*100)/$limit]
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

unset body
