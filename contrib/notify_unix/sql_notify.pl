#	<P>The script <TT>mysql_notify.pl</TT> also logs the notification, but in addition
#	it looks up the username in a DB table in order to get additional information
#	about the user. This could be used, for example, to get a user's instant messaging
#	address from a database in order to send a notification message.
#	<TT>mysql_notify.pl</TT> requires a file <TT>/etc/notify</TT> that contains
#	three lines: the DSN, username, and password to connect to the database.

use IO::Socket;
use DBI;
use Data::Dumper;
use Net::Server::Prefork;
use Unix::Syslog qw(:macros :subs);
use strict;

# A file containing the DSN, root username, and password for the root username
use constant CONFIGFILE=>'/etc/notify_unix';

# The table to look up the user's notification address in
use constant USERS_TABLE => 'Users';
# The field name in the table that contains the user's email user id
#   (must be unique.)
use constant USER_FLD => 'UserName';
# The field name in the table that contains the user's notification address
use constant NOTIFY_FLD => 'NotifyAddr';

#------------------------------------------------------------
# Grab login params from command line
open (CONFIG, '<'.CONFIGFILE) || die 'Failed to open config file '.CONFIGFILE;
chomp (my ($D_DSN, $D_LOGIN, $D_PASSWORD) = <CONFIG>);
close CONFIG;

my ($dbh,$sth) = undef;

Unix::Syslog::openlog('notify_unix', LOG_PID | LOG_CONS, LOG_DAEMON);

my $Server = Net::Server::Prefork->new;
$Server->set_path('/var/imap/');
$Server->set_pid_name('notify_unix.pid');
$Server->set_socket_name('socket/notify');
$Server->set_log_name("notify_unix");
$Server->set_num_prefork(5);

$Server->set_user(scalar getpwnam('cyrus'));
$Server->set_group(scalar getgrnam('mail'));

$Server->set_on_connect(\&sql_notify);

$Server->start();
$sth->finish() if $sth;
$dbh->disconnect if $dbh;

sub db_connect {
  # Create connection to database.
  #   This doesn't do anything if already connected.
  if (!$dbh || $DBI::errstr || !$dbh->{Active}) {
    Unix::Syslog::syslog LOG_INFO, "Connecting to database", 0;
    $sth->finish() if $sth;
    $dbh->disconnect() if $dbh;
    $dbh = undef; # Some drivers (e.g. DBD::Sybase) need this
    $dbh = DBI->connect ($D_DSN, $D_LOGIN, $D_PASSWORD)
      || syslog LOG_ERR, 'Failed to connect to database';
    # Create statement handle
    if ($dbh) {
      $sth = $dbh->prepare(
        'SELECT ' .NOTIFY_FLD. ' FROM ' . USERS_TABLE . ' WHERE ' .USER_FLD. '=?'
      ) || syslog LOG_ERR, 'Failed to create statement handle';
    }
  }
  # If anything didn't work, wait a while and try again
  if ($DBI::errstr) {
    Unix::Syslog::syslog LOG_ERR, "No DB connection--reconnecting", 0;
    sleep 10;
    # Avoids recursion with a 'goto' (I think)--avoid filling up stack space
    goto &db_connect;
  }
}

#------------------------------------------------------------
# Get the password corresponding with this user
sub get_rows {
  my $username=$_[0];
  my @rows=undef;
  db_connect();
  # Try and exec the query. If we can't, we've probably lost our DB connection...
  while (!$sth->execute($username)) {
   #  ... so wait a while and get it back.
    sleep 10;
    db_connect();
  }
  if (defined $DBI::errstr) {
    Unix::Syslog::syslog LOG_ERR, $DBI::errstr;
    return ();
  }
  @rows=$sth->fetchrow_array;
  return @rows;
}

sub sql_notify {
  my $sock = shift;

  my $Class = $sock->getline();
  my $Instance = $sock->getline();
  my $User = $sock->getline();
  my $Mailbox = $sock->getline();
  my $Message = join("\n",$sock->getlines());
  # Hmmm... there seems to be a trailling space we have to remove...
  $User =~ s/\s$//;

  my @rows = get_rows($User);
  $#rows<1 || 
    syslog LOG_ERR, "Non-unique rows for user $User";
  my $row = $rows[0];
  # Do the notification, if we successfully looked up the user in the DB
  if ($row) {
    ##############################
    ### TODO: Do notification here
    ##############################
    syslog LOG_ERR, "Notification for $User with $row";
  }

  $sock->close;
}
