#!/usr/bin/perl -w
# This is a Cyrus notifier daemon framework that goes with notify_unix.c.
#   You need to add your actual notification code in sub do_socket_stuff.
#
# The preforking server code is based on The Perl Cookbook (O'Reilly), Recipe 17.12.
#   If you haven't already, get The Perl CD Bookshelf (O'Reilly), which includes
#   a nicely hyperlinked version of Perl Cookbook, amongst other things.
#   See http://www1.fatbrain.com/asp/bookinfo/bookinfo.asp?theisbn=1565924622
#
# Standard Perl idioms for creating a daemon are used. See
#   http://www.webreference.com/perl/tutorial/9/index.html
#   for a good reference. Also see perldoc perlipc
#
# The remaining code is (C) Jeremy Howard <jhoward@fastmail.fm>, GPL2 license.
#
# If you just want to _use_ an IMAP server with notification, try out
#   http://www.fastmail.fm

use strict;
use IO::Socket;
use Symbol;
use Unix::Syslog qw(:macros :subs);
use POSIX qw(setuid sigprocmask setsid SIGINT SIG_BLOCK SIG_UNBLOCK);
use constant PATH=>'/tmp';
use constant SOCKETNAME=>'/tmp/notify_unix';
use constant PIDNAME=>'/tmp/notify_unix.pid';
use constant CYRUSUSER=>'cyrus';
use constant CYRUSGRP=>'mail';

#------------------------------------------------------------
# global variables
my $PREFORK                = 3;        # number of children to maintain
my $MAX_CLIENTS_PER_CHILD  = 500;      # number of clients each child should process
my %children               = ();       # keys are current child process IDs
my $children               = 0;        # current number of children

if (-e PIDNAME) {
  my $CurrPid;
  open PID_FH, PIDNAME;
  $CurrPid = <PID_FH>;
  close PID_FH;
  die "It looks like I'm already running as PID " . $CurrPid . 
    "\nIf this isn't right, delete " . PIDNAME . "\n";
}

my $CyrusId = getpwnam(CYRUSUSER);
my $CyrusGrpId = getgrnam(CYRUSGRP);

#------------------------------------------------------------
# Fork off a new process in a safe way, and return the $pid
sub SafeFork {
  my ($sigset, $pid);
  
  # block signal for fork
  $sigset = POSIX::SigSet->new(SIGINT);
  sigprocmask(SIG_BLOCK, $sigset)
      or die "Can't block SIGINT for fork: $!\n";
  
  # Fork this process, to actually create the child
  die "fork: $!" unless defined ($pid = fork);
  if (!$pid) {
    # I'm the child--make me safe
    $SIG{INT} = 'DEFAULT';      # make SIGINT kill us as it did before
    open STDIN,  '/dev/null' or die "Can't read /dev/null: $!";
    open STDOUT, '>/dev/null';
    open STDERR, '>/dev/null';
    # Change to root dir to avoid locking a mounted file system
    chdir '/'                 or die "Can't chdir to /: $!";
    # Turn process into session leader, and ensure no controlling terminal
    POSIX::setsid();
  }
  sigprocmask(SIG_UNBLOCK, $sigset)
      or die "Can't unblock SIGINT for fork: $!\n";
  return $pid;
}

#------------------------------------------------------------
# Set up socket
Unix::Syslog::openlog("notify_unix", LOG_PID | LOG_CONS, LOG_DAEMON);
unlink (SOCKETNAME);
# Save current default permissions for this process, and remove default 
#   permissions before creating socket
setuid $CyrusId;
POSIX::setgid $CyrusGrpId;
$>=$CyrusId;
$<=$CyrusId;
$(=$CyrusGrpId;
$)=$CyrusGrpId;
my $oldumask = umask(0027);
my $listen = undef;
# Try and listen on socket defined by SOCKETNAME
if (!($listen = IO::Socket::UNIX->new(
  Type=>SOCK_STREAM, Local=>SOCKETNAME, Listen=>0))) { 
  Unix::Syslog::syslog LOG_ERR, "Could not open listen socket.", 0;
  die "Could not open listen socket."; 
}
# Restore this process's permissions
umask($oldumask);
# Record separator = empty lines (see perldoc perlvar)
$/ = "\000";

#------------------------------------------------------------
# takes care of dead children
sub REAPER {                        
  $SIG{CHLD} = \&REAPER;
  my $pid = wait;
  $children --;
  delete $children{$pid};
}

#------------------------------------------------------------
# signal handler for SIGINT
sub HUNTSMAN {                      
  local($SIG{CHLD}) = 'IGNORE';   # we're going to kill our children
  unlink (SOCKETNAME);
  unlink (PIDNAME);
  syslog LOG_ERR, "Exiting on INT signal.";
  kill 'INT' => keys %children;
  exit;                           # clean up with dignity
}
    
#------------------------------------------------------------
# Create child process--this will become the dispatcher process
my $PID = SafeFork();
if ($PID) {
  # Record child pid for killing later
  open PID_FH, '>'.PIDNAME;
  print PID_FH $PID;
  close PID_FH;
  # Kill the parent process
  $PID && exit(0);
}

# Fork off our children.
for (1 .. $PREFORK) {
  make_new_child();
}

# Install signal handlers.
$SIG{CHLD} = \&REAPER;
$SIG{INT}  = \&HUNTSMAN;

#------------------------------------------------------------
# And maintain the population.
while (1) {
  sleep;                          # wait for a signal (i.e., child's death)
  for (my $i = $children; $i < $PREFORK; $i++) {
    make_new_child();           # top up the child pool
  }
}

#------------------------------------------------------------
# This is the bit specfic to socket apps. Everything in SafeFork is generic
sub make_new_child {
  my $pid = SafeFork();
  
  if ($pid) {
    $children{$pid} = 1;
    $children++;
    return;
  } else {
    setuid $CyrusId;
    $>=$CyrusId; 
    $<=$CyrusId;
    chroot '/dev/null';

    # handle connections until we've reached $MAX_CLIENTS_PER_CHILD
    for (my $i=0; $i < $MAX_CLIENTS_PER_CHILD; $i++) {
      my $sock = $listen->accept()     or last;
      $sock->autoflush(1);
      # do the actual work!
      do_socket_stuff($sock);
    }

    # tidy up gracefully and finish
    # this exit is VERY important, otherwise the child will become
    # a producer of more and more children, forking yourself into
    # process death.
    exit;
  }
}

#------------------------------------------------------------
# This is the app specfic bit. 
sub do_socket_stuff {
  my ($sock) = @_;

  my $Class = $sock->getline();
  my $Instance = $sock->getline();
  my $User = $sock->getline();
  my $Mailbox = $sock->getline();
  my $Message = $sock->getline();

  ###
  # TODO: Put your code here!
  ###

  syslog LOG_ERR, "Notifying $Class $Instance $User $Mailbox $Message";

  $sock->close;
}
