use IO::Socket;
use Data::Dumper;
use Net::Server::Prefork;
use Unix::Syslog qw(:macros :subs);
use strict;

sub log_connection {
  my $sock = shift;

  my $Class = $sock->getline();
  my $Instance = $sock->getline();
  my $User = $sock->getline();
  my $Mailbox = $sock->getline();
  my $Message = join("\n",$sock->getlines());

  syslog LOG_ERR, "Notifying Class $Class Instance $Instance User $User MB $Mailbox Message $Message";

  $sock->close;
}

Unix::Syslog::openlog('notify_unix', LOG_PID | LOG_CONS, LOG_DAEMON);

my $Server = Net::Server::Prefork->new;
$Server->set_path('/var/imap/');
$Server->set_pid_name('notify_unix.pid');
$Server->set_socket_name('socket/notify');
$Server->set_log_name("notify_unix");
$Server->set_num_prefork(2);

$Server->set_user(scalar getpwnam('cyrus'));
$Server->set_group(scalar getgrnam('mail'));

$Server->set_on_connect(\&log_connection);

$Server->start();

