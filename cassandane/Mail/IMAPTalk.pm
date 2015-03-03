package Mail::IMAPTalk;

=head1 NAME

Mail::IMAPTalk - IMAP client interface with lots of features

=head1 SYNOPSIS

  use Mail::IMAPTalk;

  $IMAP = Mail::IMAPTalk->new(
      Server   => $IMAPServer,
      Username => 'foo',
      Password => 'bar',
  ) || die "Failed to connect/login to IMAP server";

  # Append message to folder
  open(my $F, 'rfc822msg.txt');
  $IMAP->append($FolderName, $F) || dir $@;
  close($F);

  # Select folder and get first unseen message
  $IMAP->select($FolderName) || die $@;
  $MsgId = $IMAP->search('not', 'seen')->[0];

  # Get message envelope and print some details
  $MsgEV = $IMAP->fetch($MsgId, 'envelope')->{$MsgId}->{envelope};
  print "From: " . $MsgEv->{From};
  print "To: " . $MsgEv->{To};
  print "Subject: " . $MsgEv->{Subject};

  # Get message body structure
  $MsgBS = $IMAP->fetch($MsgId, 'bodystructure')->{$MsgId}->{bodystructure};

  # Find imap part number of text part of message
  $MsgTxtHash = Mail::IMAPTalk::find_message($MsgBS);
  $MsgPart = $MsgTxtHash->{text}->{'IMAP-Partnum'};

  # Retrieve message text body
  $MsgTxt = $IMAP->fetch($MsgId, "body[$MsgPart]")->{$MsgId}->{body};

  $IMAP->logout();

=head1 DESCRIPTION

This module communicates with an IMAP server. Each IMAP server command
is mapped to a method of this object.

Although other IMAP modules exist on CPAN, this has several advantages
over other modules.

=over 4

=item *

It parses the more complex IMAP structures like envelopes and body
structures into nice Perl data structures.

=item *

It correctly supports atoms, quoted strings and literals at any
point. Some parsers in other modules aren't fully IMAP compatiable
and may break at odd times with certain messages on some servers.

=item *

It allows large return values (eg. attachments on a message)
to be read directly into a file, rather than into memory.

=item *

It includes some helper functions to find the actual text/plain
or text/html part of a message out of a complex MIME structure.
It also can find a list of attachements, and CID links for HTML
messages with attached images.

=item *

It supports decoding of MIME headers to Perl utf-8 strings automatically,
so you don't have to deal with MIME encoded headers (enabled optionally).

=back

While the IMAP protocol does allow for asynchronous running of commands, this
module is designed to be used in a synchronous manner. That is, you issue a
command by calling a method, and the command will block until the appropriate
response is returned. The method will then return the parsed results from
the given command.

=cut

# Export {{{
require Exporter;
@ISA = qw(Exporter);
%EXPORT_TAGS = (
  Default => [ qw(get_body_part find_message build_cid_map generate_cid) ]
);
Exporter::export_ok_tags('Default');

my $AlwaysTrace = 0;

sub import {
  # Test for special case if need UTF8 support
  our $AlreadyLoadedEncode;
  my $Class = shift(@_);

  my %Parameters = map { $_ => 1 } @_;

  if (delete($Parameters{':utf8support'})) {
    if (!$AlreadyLoadedEncode) {
      eval "use Encode qw(decode decode_utf8);";
      $AlreadyLoadedEncode = 1;
    }
  }

  if (delete($Parameters{':trace'})) {
   $AlwaysTrace = 1;
  }

  @_ = ($Class, keys(%Parameters));

  goto &Exporter::import;
}

our $VERSION = '2.01';
# }}}

# Use modules {{{
use Fcntl qw(:DEFAULT);
use Socket;
use IO::Select;
use IO::Handle;
use IO::Socket;
use Digest;
use Data::Dumper;

# Choose the best socket class to use (all of these are sub-classes of IO::Socket)
my $DefSocketClass;
BEGIN {
  for (qw(IO::Socket::IP IO::Socket::INET6 IO::Socket::INET)) {
    if (eval "use $_; 1;") { $DefSocketClass = $_; last; }
  }
}

# Use Time::HiRes if available to handle select restarts
eval 'use Time::HiRes qw(time);';

use strict;
use warnings;
# }}}

=head1 CLASS OVERVIEW

The object methods have been broken in several sections.

=head2 Sections

=over 4

=item CONSTANTS

Lists the available constants the class uses.

=item CONSTRUCTOR

Explains all the options available when constructing a new instance of the
C<Mail::IMAPTalk> class.

=item CONNECTION CONTROL METHODS

These are methods which control the overall IMAP connection object, such
as logging in and logging out, how results are parsed, how folder names and
message id's are treated, etc.

=item IMAP FOLDER COMMAND METHODS

These are methods to inspect, add, delete and rename IMAP folders on
the server.

=item IMAP MESSAGE COMMAND METHODS

These are methods to retrieve, delete, move and add messages to/from
IMAP folders.

=item HELPER METHODS

These are extra methods that users of this class might find useful. They
generally do extra parsing on returned structures to provide higher
level functionality.

=item INTERNAL METHODS

These are methods used internally by the C<Mail::IMAPTalk> object to get work
done. They may be useful if you need to extend the class yourself. Note that
internal methods will always 'die' if they encounter any errors.

=item INTERNAL SOCKET FUNCTIONS

These are functions used internally by the C<Mail::IMAPTalk> object 
to read/write data to/from the IMAP connection socket. The class does
its own buffering so if you want to read/write to the IMAP socket, you
should use these functions.

=item INTERNAL PARSING FUNCTIONS

These are functions used to parse the results returned from the IMAP server
into Perl style data structures.

=back

=head2 Method results

All methods return undef on failure. There are four main modes of failure:

=over 4

=item 1. An error occurred reading/writing to a socket. Maybe the server
closed it, or you're not connected to any server.

=item 2. An error occurred parsing the response of an IMAP command. This is
usually only a problem if your IMAP server returns invalid data.

=item 3. An IMAP command didn't return an 'OK' response.

=item 4. The socket read operation timed out waiting for a response from
the server.

=back

In each case, some readable form of error text is placed in $@, or you
can call the C<get_last_error()> method. For commands which return
responses (e.g. fetch, getacl, etc), the result is returned. See each
command for details of the response result. For commands
with no response but which succeed (e.g. setacl, rename, etc) the result
'ok' is generally returned.

=head2 Method parameters

All methods which send data to the IMAP server (e.g. C<fetch()>, C<search()>,
etc) have their arguments processed before they are sent. Arguments may be
specified in several ways:

=over 4

=item B<scalar>

The value is first checked and quoted if required. Values containing
[\000\012\015] are turned into literals, values containing
[\000-\040\{\} \%\*\"] are quoted by surrounding with a "..." pair
(any " themselves are turned into \"). undef is turned into NIL

=item B<file ref>

The contents of the file is sent as an IMAP literal. Note that
because IMAPTalk has to know the length of the file being sent,
this must be a true file reference that can be seeked and not
just some stream. The entire file will be sent regardless of the
current seek point.

=item B<scalar ref>

The string/data in the referenced item should be sent as is, no quoting will
occur, and the data won't be sent as quoted or as a literal regardless
of the contents of the string/data.

=item B<array ref>

Emits an opening bracket, and then each item in the array separated
by a space, and finally a closing bracket. Each item in the array
is processed by the same methods, so can be a scalar, file ref,
scalar ref, another array ref, etc.

=item B<hash ref>

The hash reference should contain only 1 item. The key is a text
string which specifies what to do with the value item of the hash.

=over 4

=item * 'Literal'

The string/data in the value is sent as an IMAP literal
regardless of the actual data in the string/data.

=item * 'Quote'

The string/data in the value is sent as an IMAP quoted string
regardless of the actual data in the string/data.

=back

Examples:

    # Password is automatically quoted to "nasty%*\"passwd"
    $IMAP->login("joe", 'nasty%*"passwd');
    # Append $MsgTxt as string
    $IMAP->append("inbox", { Literal => $MsgTxt })
    # Append MSGFILE contents as new message
    $IMAP->append("inbox", \*MSGFILE ])

=back

=cut

=head1 CONSTANTS

These constants relate to the standard 4 states that an IMAP connection can
be in. They are passed and returned from the C<state()> method. See RFC 3501
for more details about IMAP connection states.

=over 4

=item I<Unconnected>

Current not connected to any server.

=item I<Connected>

Connected to a server, but not logged in.

=item I<Authenticated>

Connected and logged into a server, but not current folder.

=item I<Selected>

Connected, logged in and have 'select'ed a current folder.

=back

=cut

# Constants for the possible states the connection can be in {{{
# Object not connected
use constant Unconnected => 0;
# connected; not logged in
use constant Connected => 1;
# logged in; no mailbox selected
use constant Authenticated => 2;
# mailbox selected
use constant Selected => 3;

# What a link break is on the network connection
use constant LB => "\015\012";
use constant LBLEN => length(LB);

# Regexps used to determine if header is MIME encoded (we remove . from
#  especials because of dumb ANSI_X3.4-1968 encoding)
my $RFC2047Token = qr/[^\x00-\x1f\(\)\<\>\@\,\;\:\"\/\[\]\?\=\ ]+/;
my $NeedDecodeUTF8Regexp = qr/=\?$RFC2047Token\?$RFC2047Token\?[^\?]*\?=/;

# Known untagged responses
my %UntaggedResponses = map { $_ => 1 } qw(exists expunge recent);

# Default responses
my %RespDefaults = ('annotation' => 'hash', 'metadata' => 'hash', 'fetch' => 'hash', 'list' => 'array', 'lsub' => 'array', 'sort' => 'array', 'search' => 'array');

# }}}

=head1 CONSTRUCTOR

=over 4

=cut

=item I<Mail::IMAPTalk-E<gt>new(%Options)>

Creates new Mail::IMAPTalk object. The following options are supported.

=item B<Connection Options>

=over 4

=item B<Server>

The hostname or IP address to connect to. This must be supplied unless
the B<Socket> option is supplied.

=item B<Port>

The port number on the host to connect to. Defaults to 143 if not supplied
or 993 if not supplied and UseSSL is true.

=item B<UseSSL>

If true, use an IO::Socket::SSL connection. All other SSL_* arguments
are passed to the IO::Socket::SSL constructor.

=item B<Socket>

An existing socket to use as the connection to the IMAP server. If you
supply the B<Socket> option, you should not supply a B<Server> or B<Port>
option.

This is useful if you want to create an SSL socket connection using
IO::Socket::SSL and then pass in the connected socket to the new() call.

It's also useful in conjunction with the C<release_socket()> method
described below for reusing the same socket beyond the lifetime of the IMAPTalk
object. See a description in the section C<release_socket()> method for
more information.

You must have write flushing enabled for any
socket you pass in here so that commands will actually be sent,
and responses received, rather than just waiting and eventually
timing out. you can do this using the Perl C<select()> call and
$| ($AUTOFLUSH) variable as shown below.

  my $ofh = select($Socket); $| = 1; select ($ofh);

=item B<UseBlocking>

For historical reasons, when reading from a socket, the module
sets the socket to non-blocking and does a select(). If you're
using an SSL socket that doesn't work, so you have to set
UseBlocking to true to use blocking reads instead.

=item B<State>

If you supply a C<Socket> option, you can specify the IMAP state the
socket is currently in, namely one of 'Unconnected', 'Connected',
'Authenticated' or 'Selected'. This defaults to 'Connected' if not
supplied and the C<Socket> option is supplied.

=item B<ExpectGreeting>

If supplied and true, and a socket is supplied via the C<Socket>
option, checks that a greeting line is supplied by the server
and reads the greeting line.

=back

=item B<Login Options>

=over 4

=item B<Username>

The username to connect to the IMAP server as. If not supplied, no login
is attempted and the IMAP object is left in the B<CONNECTED> state.
If supplied, you must also supply the B<Password> option and a login
is attempted. If the login fails, the connection is closed and B<undef>
is returned. If you want to do something with a connection even if the
login fails, don't pass a B<Username> option, but instead use the B<login>
method described below.

=item B<Password>

The password to use to login to the account.

=back

=item B<IMAP message/folder options>

=over 4

=item B<Uid>

Control whether message ids are message uids or not. This is 1 (on) by
default because generally that's how most people want to use it. This affects
most commands that require/use/return message ids (e.g. B<fetch>, B<search>,
B<sort>, etc)

=item B<RootFolder>

If supplied, sets the root folder prefix. This is the same as calling
C<set_root_folder()> with the value passed. If no value is supplied,
C<set_root_folder()> is called with no value. See the C<set_root_folder()>
method for more details.

=item B<Separator>

If supplied, sets the folder name text string separator character. 
Passed as the second parameter to the C<set_root_folder()> method.

=item B<CaseInsensitive>

If supplied, passed along with RootFolder to the C<set_root_folder()>
method.

=item B<AltRootRegexp>

If supplied, passed along with RootFolder to the C<set_root_folder()>
method.

=back

Examples:

  $imap = Mail::IMAPTalk->new(
            Server          => 'foo.com',
            Port            => 143,
            Username        => 'joebloggs',
            Password        => 'mypassword',
            Separator       => '.',
            RootFolder      => 'inbox',
            CaseInsensitive => 1)
          || die "Connection to foo.com failed. Reason: $@";

  $imap = Mail::IMAPTalk->new(
            Socket => $SSLSocket,
            State  => Mail::IMAPTalk::Authenticated,
            Uid    => 0)
          || die "Could not query on existing socket. Reason: $@";

=cut
sub new {
  my $Proto = shift;
  my $Class = ref($Proto) || $Proto;
  my %Args = @_;

  # Two main possible new() modes. Either connect to server
  #   or use existing socket passed
  $Args{Server} || $Args{Socket}
    || die "No 'Server' or 'Socket' specified";
  $Args{Server} && $Args{Socket}
    && die "Can not specify 'Server' and 'Socket' simultaneously";

  # Set ourself to empty to start with
  my $Self = {};
  bless ($Self, $Class);

  # Empty buffer
  $Self->{ReadBuf} = '';

  # Create new socket to server
  my $Socket;
  if ($Args{Server}) {

    # Set starting state
    $Self->state(Unconnected);

    my %SocketOpts;
    my $DefaultPort = 143;
    my $SocketClass = $DefSocketClass;

    if (my $SSLOpt = $Args{UseSSL}) {
      $SSLOpt = $SSLOpt eq '1' ? '' : " qw($SSLOpt)";
      eval "use IO::Socket::SSL$SSLOpt; 1;" || return undef;
      $SocketClass = "IO::Socket::SSL";
      $DefaultPort = 993;
      $SocketOpts{$_} = $Args{$_} for grep { /^SSL_/ } keys %Args;
    }

    $SocketOpts{PeerHost} = $Self->{Server} = $Args{Server} || die "No Server name given";
    $SocketOpts{PeerPort} = $Self->{Port} = $Args{Port} || $DefaultPort;

    $Socket = ${SocketClass}->new(%SocketOpts) || return undef;

    # Force flushing after every write to the socket
    my $ofh = select($Socket); $| = 1; select ($ofh);

    # Set to connected state
    $Self->state(Connected);
  }

  # We have an existing socket
  else {
    # Copy socket
    $Socket = $Args{Socket};
    delete $Args{Socket};

    # Set state
    $Self->state(exists $Args{State} ? $Args{State} : Connected);
  }

  $Self->{Socket} = $Socket;

  # Save socket for later use and create IO::Select
  $Self->{Select} = IO::Select->new();
  $Self->{Select}->add($Socket);
  $Self->{LocalFD} = fileno($Socket);
  $Self->{UseBlocking} = $Args{UseBlocking};
  $Self->{Pedantic} = $Args{Pedantic};

  # Do this now, so we trace greeting line as well
  $Self->set_tracing($AlwaysTrace);

  # Process greeting
  if ($Args{Server} || $Args{ExpectGreeting}) {
    $Self->{CmdId} = "*";
    my ($CompletionResp, $DataResp) = $Self->_parse_response('');
    return undef if $CompletionResp !~ /^ok/i;
  }

  # Start counter when sending commands
  $Self->{CmdId} = 1;

  # Set base modes
  $Self->uid(exists($Args{Uid}) ? $Args{Uid} : 1);
  $Self->parse_mode(Envelope => 1, BodyStructure => 1, Annotation => 1);
  $Self->{CurrentFolder} = '';
  $Self->{CurrentFolderMode} = '';

  # Login first if specified
  if ($Args{Username}) {
    # If login fails, just return undef
    $Self->login(@Args{'Username', 'Password'}) || return undef;
  }

  # Set root folder and separator (if supplied)
  $Self->set_root_folder(
    $Args{RootFolder}, $Args{Separator}, $Args{CaseInsensitive}, $Args{AltRootRegexp});

  return $Self;
}

=back
=cut

=head1 CONNECTION CONTROL METHODS

=over 4
=cut

=item I<login($UnqName, $Password)>

Attempt to login user specified username and password.

Currently there is only plain text password login support. If someone can
give me a hand implementing others (like DIGEST-MD5, CRAM-MD5, etc) please
contact me (see details below).

=cut
sub login {
  my $Self = shift;
  my ($User, $Pwd) = @_;
  my $PwdArr = { 'Quote' => $Pwd };

  # Clear cached capability responses and the like
  delete $Self->{Cache};

  # Call standard command. Return undef if login failed
  $Self->_imap_cmd("login", 0, "", $User, $PwdArr)
    || return undef;

  # Set to authenticated if successful
  $Self->state(Authenticated);

  return 1;
}

=item I<logout()>

Log out of IMAP server. This usually closes the servers connection as well.

=cut
sub logout {
  my $Self = shift;
  # Callback to say we're switching folders
  $Self->cb_switch_folder($Self->{CurrentFolder}, '');
  $Self->_imap_cmd('logout', 0, '');
  # Returns the socket, which we immediately discard to close
  $Self->release_socket(1);
  return 1;
}

=item I<state(optional $State)>

Set/get the current IMAP connection state. Returned or passed value should be
one of the constants (Unconnected, Connected, Authenticated, Selected).

=cut
sub state {
  my $Self = shift;
  $Self->{State} = $_[0] if defined $_[0];
  return (defined($Self->{State}) ? $Self->{State} : '');
}

=item I<uid(optional $UidMode)>

Get/set the UID status of all UID possible IMAP commands.
If set to 1, all commands that can take a UID are set to 'UID Mode',
where any ID sent to IMAPTalk is assumed to be a UID.

=cut
sub uid {
  $_[0]->{Uid} = $_[1];
  return 1;
}

=item I<capability()>

This method returns the IMAP servers capability command results.
The result is a hash reference of (lc(Capability) => 1) key value pairs.
This means you can do things like:

  if ($IMAP->capability()->{quota}) { ... }

to test if the server has the QUOTA capability. If you just want a list of
capabilities, use the Perl 'keys' function to get a list of keys from the
returned hash reference.

=cut
sub capability {
  my $Self = shift;

  # If we've already executed the capability command once, just return the results
  return $Self->{Cache}->{capability}
    if exists $Self->{Cache}->{capability};

  # Otherwise execute capability command
  my $Capability = $Self->_imap_cmd("capability", 0, "capability");

  # Better be a hash-ref...
  ($Capability && ref($Capability) eq 'HASH') || return {};

  # Save for any future queries and return
  return ($Self->{Cache}->{capability} = $Capability);
}

=item I<namespace()>

Returns the result of the IMAP servers namespace command.

=cut
sub namespace {
  my $Self = shift;

  # If we've already executed the capability command once, just return the results
  return $Self->{Cache}->{namespace}
    if exists $Self->{Cache}->{namespace};

  $Self->_require_capability('namespace') || return undef;

  # Otherwise execute capability command
  my $Namespace = $Self->_imap_cmd("namespace", 0, "namespace");

  # Save for any future queries and return
  return ($Self->{Cache}->{namespace} = $Namespace);
}

=item I<noop()>

Perform the standard IMAP 'noop' command which does nothing.

=cut
sub noop {
  my $Self = shift;
  return $Self->_imap_cmd("noop", 0, "", @_);
}

=item I<enable($option)>

Enabled the given imap extension

=cut
sub enable {
  my $Self = shift;
  my $Feature = shift;

  # If we've already executed the enable command once, just return the results
  return $Self->{Cache}->{enable}->{$Feature}
    if exists $Self->{Cache}->{enable}->{$Feature};

  $Self->_require_capability($Feature) || return undef;

  my $Result = $Self->_imap_cmd("enable", 0, "enabled", $Feature);
  $Self->{Cache}->{enable} = $Result;

  return $Result && $Result->{$Feature};
}

=item I<is_open()>

Returns true if the current socket connection is still open (e.g. the socket
hasn't been closed this end or the other end due to a timeout).

=cut
sub is_open {
  my $Self = shift;

  $Self->_trace("A: is_open test\n") if $Self->{Trace};

  while (1) {

    # Ensure no data was left in our own read buffer
    if ($Self->{ReadLine}) {
      $Self->_trace("A: unexpected data in read buffer - '" .$Self->{ReadLine}. "'\n")
        if $Self->{Trace};
      die "IMAPTalk: Unexpected data in read buffer '" . $Self->{ReadLine} . "'";
    }
    $Self->{ReadLine} = undef;

    # See if there's any data to read
    local $Self->{Timeout} = 0;

    # If no sockets with data, must be blocked, so must be connected
    my $Atom = eval { $Self->_next_atom(); };

    # If a timeout, socket is still connected and open
    if ($@ && ($@ =~ /timed out/)) {
      $Self->_trace("A: is_open test received timeout, still open\n")
        if $Self->{Trace};
      return 1;
    }

    # Other error, assume it's closed
    if ($@) {
      $Self->_trace("A: is_open test received error - $@\n")
        if $Self->{Trace};
      $Self->{Socket}->close() if $Self->{Socket};
      $Self->{Socket} = undef;
      $Self->state(Unconnected);
      return undef;
    }

    # There was something, find what it was
    $Atom = $Self->_remaining_line();

    $Self->_trace("A: is_open test returned data - '$Atom'\n")
      if $Self->{Trace};

    $Atom || die "IMAPTalk: Unexpected response while checking connection - $Atom";

    # If it's a bye, we're being closed
    if ($Atom =~ /^bye/i) {
      $Self->_trace("A: is_open test received 'bye' response\n")
        if $Self->{Trace};
      $Self->{Socket}->close();
      $Self->{Socket} = undef;
      $Self->state(Unconnected);
      return undef;
    }

    # Otherwise it was probably some sort of alert,
    #  check again
  }

}

=item I<set_root_folder($RootFolder, $Separator, optional $CaseInsensitive, $AltRootRegexp)>

Change the root folder prefix. Some IMAP servers require that all user
folders/mailboxes live under a root folder prefix (current versions of
B<cyrus> for example use 'INBOX' for personal folders and 'user' for other
users folders). If no value is specified, it sets it to ''. You might
want to use the B<namespace()> method to find out what roots are
available. The $CaseInsensitive argument is a flag that determines
whether the root folder should be matched in a case sensitive or
insensitive way. See below.

Setting this affects all commands that take a folder argument. Basically
if the foldername begins with root folder prefix (case sensitive or
insensitive based on the second argument), it's left as is,
otherwise the root folder prefix and separator char are prefixed to the
folder name.

The AltRootRegexp is a regexp that if the start of the folder name matches,
does not have $RootFolder preprended. You can use this to protect
other namespaces in your IMAP server.

Examples:

  # This is what cyrus uses
  $IMAP->set_root_folder('inbox', '.', 1, 'user');

  # Selects 'Inbox' (because 'Inbox' eq 'inbox' case insensitive)
  $IMAP->select('Inbox');      
  # Selects 'inbox.blah'
  $IMAP->select('blah');
  # Selects 'INBOX.fred' (because 'INBOX' eq 'inbox' case insensitive)
  #IMAP->select('INBOX.fred'); # Selects 'INBOX.fred'
  # Selects 'user.john' (because 'user' is alt root)
  #IMAP->select('user.john'); # Selects 'user.john'

=cut
sub set_root_folder {
  my ($Self, $RootFolder, $Separator, $CaseInsensitive, $AltRootRegexp) = @_;

  $RootFolder = '' if !defined($RootFolder);
  $Separator = '' if !defined($Separator);
  $AltRootRegexp = '' if !defined($AltRootRegexp);

  # Strip of the Separator, if the IMAP-Server already appended it
  $RootFolder =~ s/\Q$Separator\E$//;

  $Self->{RootFolder} = $RootFolder;
  $Self->{AltRootRegexp} = $AltRootRegexp;
  $Self->{Separator} = $Separator;
  $Self->{CaseInsensitive} = $CaseInsensitive;

  # A little tricky. We want to promote INBOX.blah -> blah, but
  # we have to be careful not to loose things like INBOX.inbox
  # which we leave alone

  # INBOX             -> INBOX
  # INBOX.blah        -> blah
  # INBOX.inbox       -> INBOX.inbox
  # INBOX.INBOX       -> INBOX.INBOX
  # INBOX.inbox.inbox -> INBOX.inbox.inbox
  # INBOX.inbox.blah  -> INBOX.blah
  # user.xyz          -> user.xyz

  # RootFolderMatch
  # If folder passed in doesn't match this, then prepend $RootFolder . $Separator
  # eg prepend inbox. if folder !/^inbox(\.inbox)*$|^user$|^user\./

  # UnrootFolderMatch
  # If folder returned matches this, strip $RootFolder . $Separator
  # eg strip inbox. if folder /^inbox\.(?!inbox(\.inbox)*)/

  my ($RootFolderMatch, $UnrootFolderMatch, $RootFolderNormalise);
  if ($RootFolder) {
    if ($CaseInsensitive) {
      $RootFolderMatch = qr/\Q${RootFolder}\E(?i:\Q${Separator}${RootFolder}\E)*/i;
      $UnrootFolderMatch = qr/^\Q${RootFolder}${Separator}\E(?!${RootFolderMatch}$)/i;
      $RootFolderNormalise = qr/^\Q${RootFolder}\E(\Q${Separator}\E|$)/i;
    } else {
      $RootFolderMatch = qr/\Q${RootFolder}\E(?:\Q${Separator}${RootFolder}\E)*/;
      $UnrootFolderMatch = qr/^\Q${RootFolder}${Separator}\E(?!${RootFolderMatch}$)/;
      $RootFolderNormalise = qr/^\Q${RootFolder}(?:\Q${Separator}\E|$)/;
    }

    $RootFolderMatch = qr/^${RootFolderMatch}$/;
    if ($AltRootRegexp) {
      $RootFolderMatch = qr/$RootFolderMatch|^(?:${AltRootRegexp})$|^(?:${AltRootRegexp})\Q${Separator}\E/;
    }

  }
  @$Self{qw(RootFolderMatch UnrootFolderMatch RootFolderNormalise)}
    = ($RootFolderMatch, $UnrootFolderMatch, $RootFolderNormalise);

  return 1;
}

=item I<_set_separator($Separator)>

Checks if the given separator is the same as the one we used before.
If not, it calls set_root_folder to recreate the settings with the new
Separator.

=cut
sub _set_separator {
  my ($Self,$Separator) = @_;

  #Nothing to do, if we have the same Separator as before
  return 1 if (defined($Separator) && ($Self->{Separator} eq $Separator));
  return $Self->set_root_folder($Self->{RootFolder}, $Separator,
                                $Self->{CaseInsensitive}, $Self->{AltRootRegexp});
}

=item I<literal_handle_control(optional $FileHandle)>

Sets the mode whether to read literals as file handles or scalars.

You should pass a filehandle here that any literal will be read into. To
turn off literal reads into a file handle, pass a 0.

Examples:

  # Read rfc822 text of message 3 into file
  # (note that the file will have /r/n line terminators)
  open(F, ">messagebody.txt");
  $IMAP->literal_handle_control(\*F);
  $IMAP->fetch(3, 'rfc822');
  $IMAP->literal_handle_control(0);

=cut
sub literal_handle_control {
  my $Self = shift;
  $Self->{LiteralControl} = $_[0] if defined $_[0];
  return $Self->{LiteralControl} ? 1 : 0;
}

=item I<release_socket($Close)>

Release IMAPTalk's ownership of the current socket it's using so it's not
disconnected on DESTROY. This returns the socket, and makes sure that the
IMAPTalk object doesn't hold a reference to it any more and the connection
state is set to "Unconnected".

This means you can't call any methods on the IMAPTalk object any more.

If the socket is being released and being closed, then $Close is set to true.

=cut
sub release_socket {
  my $Self = shift;

  # Remove from the select object
  $Self->{Select}->remove($Self->{Socket}) if ref($Self->{Select});
  my $Socket = $Self->{Socket};

  # Delete any knowledge of the socket in our instance
  delete $Self->{Socket};
  delete $Self->{Select};

  $Self->_trace("A: Release socket, fileno=" . fileno($Socket) . "\n")
    if $Self->{Trace};

  # Set into no connection state
  $Self->state(Mail::IMAPTalk::Unconnected);

  return $Socket;
}

=item I<get_last_error()>

Returns a text string which describes the last error that occurred.

=cut
sub get_last_error {
  my $Self = shift;
  return $Self->{LastError};
}

=item I<get_last_completion_response()>

Returns the last completion response to the tagged command.

This is either the string "ok", "no" or "bad" (always lower case) 

=cut
sub get_last_completion_response {
  my $Self = shift;
  return $Self->{LastRespCode};
}

=item I<get_response_code($Response)>

Returns the extra response data generated by a previous call. This is
most often used after calling B<select> which usually generates some
set of the following sub-results.

=over 4

=item * B<permanentflags>

Array reference of flags which are stored permanently.

=item * B<uidvalidity>

Whether the current UID set is valid. See the IMAP RFC for more
information on this. If this value changes, then all UIDs in the folder
have been changed.

=item * B<uidnext>

The next UID number that will be assigned.

=item * B<exists>

Number of messages that exist in the folder.

=item * B<recent>

Number of messages that are recent in the folder.

=back

Other possible responses are B<alert>, B<newname>, B<parse>,
B<trycreate>, B<appenduid>, etc.

The values are stored in a hash keyed on the $Response item.
They're kept until either overwritten by a future response,
or explicitly cleared via clear_response_code().

Examples:

  # Select inbox and get list of permanent flags, uidnext and number
  #  of message in the folder
  $IMAP->select('inbox');
  my $NMessages = $IMAP->get_response_code('exists');
  my $PermanentFlags = $IMAP->get_response_code('permanentflags');
  my $UidNext = $IMAP->get_response_code('uidnext');

=cut
sub get_response_code {
  my ($Self, $Response) = @_;
  return $Self->{Cache}->{$Response};
}

=item I<clear_response_code($Response)>

Clears any response code information. Response code information
is not normally cleared between calls.

=cut
sub clear_response_code {
  my ($Self, $Response) = @_;
  delete $Self->{Cache}->{$Response};
  return 1;
}

=item I<parse_mode(ParseOption =E<gt> $ParseMode)>

Changes how results of fetch commands are parsed. Available
options are:

=over 4

=item I<BodyStructure>

Parse bodystructure into more Perl-friendly structure
See the B<FETCH RESULTS> section.

=item I<Envelope>

Parse envelopes into more Perl-friendly structure
See the B<FETCH RESULTS> section.

=item I<Annotation>

Parse annotation (from RFC 5257) into more Perl-friendly structure
See the B<FETCH RESULTS> section.

=item I<EnvelopeRaw>

If parsing envelopes, create To/Cc/Bcc and
Raw-To/Raw-Cc/Raw-Bcc entries which are array refs of 4
entries each as returned by the IMAP server.

=item I<DecodeUTF8>

If parsing envelopes, decode any MIME encoded headers into
Perl UTF-8 strings.

For this to work, you must have 'used' Mail::IMAPTalk with:

use Mail::IMAPTalk qw(:utf8support ...)

=back

=cut
sub parse_mode {
  my $Self = shift;

  my $ParseMode = $Self->{ParseMode} || {};
  $Self->{ParseMode} = { %$ParseMode, @_ };

}

=item I<set_tracing($Tracer)>

Allows you to trace both IMAP input and output sent to the server
and returned from the server. This is useful for debugging. Returns
the previous value of the tracer and then sets it to the passed
value. Possible values for $Tracer are:

=over 4

=item I<0>

Disable all tracing.

=item I<1>

Print to STDERR.

=item I<Code ref>

Call code ref for each line input and output. Pass line as parameter.

=item I<Glob ref>

Print to glob.

=item I<Scalar ref>

Appends to the referenced scalar.

=back

Note: literals are never passed to the tracer.

=cut
sub set_tracing {
  my $Self = shift;
  my $OldTrace = $Self->{Trace};
  $Self->{Trace} = shift;
  return $OldTrace;
}

=item I<set_unicode_folders($Unicode)>

$Unicode should be 1 or 0

Sets whether folder names are expected and returned
as perl unicode strings.

The default is currently 0, BUT YOU SHOULD NOT ASSUME THIS,
because it will probably change in the future.

If you want to work with perl unicode strings for
folder names, you should call
  $ImapTalk->set_unicode_folders(1)
and IMAPTalk will automatically encode the unicode
strings into IMAP-UTF7 when sending to the IMAP server,
and will also decode IMAP-UTF7 back into perl unicode
strings when returning results from the IMAP server.

If you want to work with folder names in IMAP-UTF7 bytes,
then call
  $ImapTalk->set_unicode_folders(0)
and IMAPTalk will leave folder names as bytes when
sending to and returning results from the IMAP server.

=cut
sub set_unicode_folders {
  my $Self = shift;
  $Self->{Cache}->{UnicodeFolders} = shift;
  if ($Self->{Cache}->{UnicodeFolders}) {
    require Encode;
    require Encode::IMAPUTF7;
  }
}

sub unicode_folders {
  my $Self = shift;
  return 0 if ! $Self->{Cache};
  return $Self->{Cache}->{UnicodeFolders} || 0;
}

=back
=cut

=head1 IMAP FOLDER COMMAND METHODS

B<Note:> In all cases where a folder name is used, 
the folder name is first manipulated according to the current root folder
prefix as described in C<set_root_folder()>.

=over 4
=cut

=item I<select($FolderName, @Opts)>

Perform the standard IMAP 'select' command to select a folder for
retrieving/moving/adding messages. If $Opts{ReadOnly} is true, the 
IMAP EXAMINE verb is used instead of SELECT.

Mail::IMAPTalk will cache the currently selected folder, and if you
issue another ->select("XYZ") for the folder that is already selected,
it will just return immediately. This can confuse code that expects
to get side effects of a select call. For that case, call ->unselect()
first, then ->select().

=cut
sub select {
  my ($Self, $Folder, %Opts) = @_;

  my $unselect = delete($Opts{unselect});
  my $ReadOnly = delete($Opts{ReadOnly});

  if ($unselect) {
    $Self->unselect();
  }

  # Are we already selected and in the same mode?
  if ($Self->_is_current_folder($Folder) &&
      ($ReadOnly ? 'read-only' : 'read-write') eq $Self->{CurrentFolderMode}) {
    return 1;
  }

  # Callback to say we're switching folders
  $Self->cb_switch_folder($Self->{CurrentFolder}, $Folder);

  # Fix the folder name to include the root suffix
  my $FixFolder = $Self->_fix_folder_name($Folder);

  $Self->clear_response_code('READ-ONLY');
  $Self->clear_response_code('READ-WRITE');

  # Do select command
  my $Cmd = $ReadOnly ? "examine" : "select";
  my $Res = $Self->_imap_cmd($Cmd, 0, "", { Quote => $FixFolder }, keys(%Opts));
  if ($Res) {
    # Set internal current folder and mode
    $Self->{CurrentFolder} = $Folder;
    my $foldermode = $Self->get_response_code('foldermode') // '';
    if ($foldermode eq 'read-write' and $ReadOnly) {
      # odd, we only asked for it to be read-only.  Buggy Cyrus 2.3.3?
      $foldermode = 'read-only';
    }
    $Self->{CurrentFolderMode} = $foldermode;

    # Set to selected state
    $Self->state(Selected);
    return $Self->{CurrentFolderMode} || $Self->{LastRespCode};
  } else {
    $Self->{CurrentFolder} = "";
    $Self->{LastError} = $@ =
      "Select failed for folder '$Folder' : $Self->{LastError}";
  }

  return undef;
}

=item I<unselect()>

Performs the standard IMAP unselect command.

=cut
sub unselect {
  my $Self = shift;

  # Callback to say we're switching folders
  $Self->cb_switch_folder($Self->{CurrentFolder}, '');

  my $Res = $Self->_imap_cmd("unselect", 0, "", @_);

  # Clear cached information about current folder
  if ($Res) {
    $Self->{CurrentFolder} = '';
    $Self->{CurrentFolderMode} = 0;
    $Self->state(Authenticated);
  }
  return $Res;
}

=item I<examine($FolderName)>

Perform the standard IMAP 'examine' command to select a folder in read only
mode for retrieving messages. This is the same as C<select($FolderName, 1)>.
See C<select()> for more details.

=cut
sub examine {
  return $_[0]->select($_[1], ReadOnly => 1);
}

=item I<create($FolderName)>

Perform the standard IMAP 'create' command to create a new folder.

=cut
sub create {
  my $Self = shift;
  $Self->cb_folder_changed($_[0]);
  return $Self->_imap_cmd("create", 0, "", $Self->_fix_folder_name(+shift), @_);
}

=item I<delete($FolderName)>

Perform the standard IMAP 'delete' command to delete a folder.

=cut
sub delete {
  my $Self = shift;
  $Self->{CurrentFolder} = "" if $Self->_is_current_folder($_[0]);
  $Self->cb_folder_changed($_[0]);
  return $Self->_imap_cmd("delete", 0, "", $Self->_fix_folder_name(+shift), @_);
}

=item I<localdelete($FolderName)>

Perform the IMAP 'localdelete' command to delete a folder (doesn't delete subfolders even of INBOX, is always immediate.

=cut
sub localdelete {
  my $Self = shift;
  $Self->{CurrentFolder} = "" if $Self->_is_current_folder($_[0]);
  $Self->cb_folder_changed($_[0]);
  return $Self->_imap_cmd("localdelete", 0, "", $Self->_fix_folder_name(+shift), @_);
}

=item I<rename($OldFolderName, $NewFolderName)>

Perform the standard IMAP 'rename' command to rename a folder.

=cut
sub rename {
  my $Self = shift;
  $Self->{CurrentFolder} = "" if $Self->_is_current_folder($_[0]);
  $Self->cb_folder_changed($_[0]);
  $Self->cb_folder_changed($_[1]);
  my $FolderName1 = $Self->_fix_folder_name(+shift);
  my $FolderName2 = $Self->_fix_folder_name(+shift);
  return $Self->_imap_cmd("rename", 0, "", $FolderName1, $FolderName2, @_);
}

=item I<list($Reference, $Name)>

Perform the standard IMAP 'list' command to return a list of available
folders.

=cut
sub list {
  my $Self = shift;
  my @Args = @_;
  # If the first argument is an array ref, then it's an extended list,
  #  and any folder list is 3rd argument, not 2nd
  my $FolderPos = ref($Args[0]) ? 2 : 1;
  if (ref($Args[$FolderPos])) {
    $Args[$FolderPos] = [ map { $Self->_fix_folder_encoding($_) } @{$Args[$FolderPos]} ];
  } else {
    $Args[$FolderPos] = $Self->_fix_folder_encoding($Args[$FolderPos]);
  }
  return $Self->_imap_cmd("list", 0, "list", @Args);
}

=item I<xlist($Reference, $Name)>

Perform the IMAP 'xlist' extension command to return a list of available
folders and their special use attributes.

=cut
sub xlist {
  my $Self = shift;
  $Self->_require_capability('xlist') || return undef;
  return $Self->_imap_cmd("xlist", 0, "xlist", @_);
}

=item I<id($key => $value, ...)>

Perform the IMAP extension command 'id'

=cut
sub id {
  my $Self = shift;
  $Self->_require_capability('id') || return undef;
  return $Self->_imap_cmd('id', 0, 'id', { Quote => \@_ });
}

=item I<lsub($Reference, $Name)>

Perform the standard IMAP 'lsub' command to return a list of subscribed
folders

=cut
sub lsub {
  my $Self = shift;
  return $Self->_imap_cmd("lsub", 0, "lsub", @_);
}

=item I<subscribe($FolderName)>

Perform the standard IMAP 'subscribe' command to subscribe to a folder.

=cut
sub subscribe {
  my $Self = shift;
  my $FolderName = $Self->_fix_folder_name(+shift);
  return $Self->_imap_cmd("subscribe", 0, "", $FolderName);
}

=item I<unsubscribe($FolderName)>

Perform the standard IMAP 'unsubscribe' command to unsubscribe from a folder.

=cut
sub unsubscribe {
  my $Self = shift;
  my $FolderName = $Self->_fix_folder_name(+shift);
  return $Self->_imap_cmd("unsubscribe", 0, "", $FolderName);
}

=item I<check()>

Perform the standard IMAP 'check' command to checkpoint the current folder.

=cut
sub check {
  my $Self = shift;
  return $Self->_imap_cmd("check", 0, "", @_);
}

=item I<setacl($FolderName, $User, $Rights)>

Perform the IMAP 'setacl' command to set the access control list
details of a folder/mailbox. See RFC 4314 for more details on the IMAP
ACL extension. $User is the user name to set the access
rights for. $Rights is either a list of absolute rights to set, or a
list prefixed by a - to remove those rights, or a + to add those rights.

=over 4

=item l - lookup (mailbox is visible to LIST/LSUB commands)

=item r - read (SELECT the mailbox, perform CHECK, FETCH, PARTIAL, SEARCH, COPY from mailbox)

=item s - keep seen/unseen information across sessions (STORE SEEN flag)

=item w - write (STORE flags other than SEEN and DELETED)

=item i - insert (perform APPEND, COPY into mailbox)

=item p - post (send mail to submission address for mailbox, not enforced by IMAP4 itself)

=item k - create mailboxes (CREATE new sub-mailboxes in any implementation-defined hierarchy, parent mailbox for the new mailbox name in RENAME)

=item x - delete mailbox (DELETE mailbox, old mailbox name in RENAME)

=item t - delete messages (set or clear \DELETED flag via STORE, set \DELETED flag during APPEND/COPY)

=item e - perform EXPUNGE and expunge as a part of CLOSE

=item a - administer (perform SETACL)

=back

Due to ambiguity in RFC 2086, some existing RFC 2086 server
implementations use the "c" right to control the DELETE command.
Others chose to use the "d" right to control the DELETE command. See
the 2.1.1. Obsolete Rights in RFC 4314 for more details.

=over 4

=item c - create (CREATE new sub-mailboxes in any implementation-defined hierarchy)

=item d - delete (STORE DELETED flag, perform EXPUNGE)

=back

The standard access control configurations for cyrus are

=over 4

=item read   = "lrs"

=item post   = "lrsp"

=item append = "lrsip"

=item write  = "lrswipcd"

=item all    = "lrswipcda"

=back

Examples:

  # Get full access for user 'joe' on his own folder
  $IMAP->setacl('user.joe', 'joe', 'lrswipcda') || die "IMAP error: $@";
  # Remove write, insert, post, create, delete access for user 'andrew'
  $IMAP->setacl('user.joe', 'andrew', '-wipcd') || die "IMAP error: $@";
  # Add lookup, read, keep unseen information for user 'paul'
  $IMAP->setacl('user.joe', 'paul', '+lrs') || die "IMAP error: $@";

=cut
sub setacl {
  my $Self = shift;
  $Self->_require_capability('acl') || return undef;
  return $Self->_imap_cmd("setacl", 0, "acl", $Self->_fix_folder_name(+shift), @_);
}

=item I<getacl($FolderName)>

Perform the IMAP 'getacl' command to get the access control list
details of a folder/mailbox. See RFC 4314 for more details on the IMAP
ACL extension. Returns an array of pairs. Each pair is
a username followed by the access rights for that user. See B<setacl>
for more information on access rights.

Examples:

  my $Rights = $IMAP->getacl('user.joe') || die "IMAP error : $@";
  $Rights = [
    'joe', 'lrs',
    'andrew', 'lrswipcda'
  ];

  $IMAP->setacl('user.joe', 'joe', 'lrswipcda') || die "IMAP error : $@";
  $IMAP->setacl('user.joe', 'andrew', '-wipcd') || die "IMAP error : $@";
  $IMAP->setacl('user.joe', 'paul', '+lrs') || die "IMAP error : $@";

  $Rights = $IMAP->getacl('user.joe') || die "IMAP error : $@";
  $Rights = [
    'joe', 'lrswipcd',
    'andrew', 'lrs',
    'paul', 'lrs'
  ];

=cut
sub getacl {
  my $Self = shift;
  $Self->_require_capability('acl') || return undef;
  return $Self->_imap_cmd("getacl", 0, "acl", $Self->_fix_folder_name(+shift), @_);
}

=item I<deleteacl($FolderName, $Username)>

Perform the IMAP 'deleteacl' command to delete all access
control information for the given user on the given folder. See B<setacl>
for more information on access rights.

Examples:

  my $Rights = $IMAP->getacl('user.joe') || die "IMAP error : $@";
  $Rights = [
    'joe', 'lrswipcd',
    'andrew', 'lrs',
    'paul', 'lrs'
  ];

  # Delete access information for user 'andrew'
  $IMAP->deleteacl('user.joe', 'andrew') || die "IMAP error : $@";

  $Rights = $IMAP->getacl('user.joe') || die "IMAP error : $@";
  $Rights = [
    'joe', 'lrswipcd',
    'paul', 'lrs'
  ];

=cut
sub deleteacl {
  my $Self = shift;
  $Self->_require_capability('acl') || return undef;
  return $Self->_imap_cmd("deleteacl", 0, "", $Self->_fix_folder_name(+shift), @_);
}

sub myrights {
  my $Self = shift;
  $Self->_require_capability('acl') || return undef;
  return $Self->_imap_cmd("myrights", 0, "myrights", $Self->_fix_folder_name(+shift), @_);
}

=item I<setquota($FolderName, $QuotaDetails)>

Perform the IMAP 'setquota' command to set the usage quota
details of a folder/mailbox. See RFC 2087 for details of the IMAP
quota extension. $QuotaDetails is a bracketed list of limit item/value
pairs which represent a particular type of limit and the value to set
it to. Current limits are:

=over 4

=item STORAGE - Sum of messages' RFC822.SIZE, in units of 1024 octets

=item MESSAGE - Number of messages

=back

Examples:

  # Set maximum size of folder to 50M and 1000 messages
  $IMAP->setquota('user.joe', '(storage 50000)') || die "IMAP error: $@";
  $IMAP->setquota('user.john', '(messages 1000)') || die "IMAP error: $@";
  # Remove quotas
  $IMAP->setquota('user.joe', '()') || die "IMAP error: $@";

=cut
sub setquota {
  my $Self = shift;
  $Self->_require_capability('quota') || return undef;
  return $Self->_imap_cmd("setquota", 0, "", $Self->_fix_folder_name(+shift), @_);
}

=item I<getquota($FolderName)>

Perform the standard IMAP 'getquota' command to get the quota
details of a folder/mailbox. See RFC 2087 for details of the IMAP
quota extension. Returns an array reference to quota limit triplets.
Each triplet is made of: limit item, current value, maximum value.

Note that this only returns the quota for a folder if it actually
has had a quota set on it. It's possible that a parent folder
might have a quota as well which affects sub-folders. Use the
getquotaroot to find out if this is true.

Examples:

  my $Result = $IMAP->getquota('user.joe') || die "IMAP error: $@";
  $Result = [
    'STORAGE', 31, 50000,
    'MESSAGE', 5, 1000
  ];

=cut
sub getquota {
  my $Self = shift;
  $Self->_require_capability('quota') || return undef;
  my $Folder = $Self->_fix_folder_name(+shift);
  my @Res = $Self->_imap_cmd("getquota", 0, "quota", $Folder, @_);
  return (ref($Res[0]) eq 'HASH') ? @{$Res[0]->{$Folder}} : @Res;
}

=item I<getquotaroot($FolderName)>

Perform the IMAP 'getquotaroot' command to get the quota
details of a folder/mailbox and possible root quota as well.
See RFC 2087 for details of the IMAP
quota extension. The result of this command is a little complex.
Unfortunately it doesn't map really easily into any structure
since there are several different responses. 

Basically it's a hash reference. The 'quotaroot' item is the
response which lists the root quotas that apply to the given
folder. The first item is the folder name, and the remaining
items are the quota root items. There is then a hash item
for each quota root item. It's probably easiest to look at
the example below.

Examples:

  my $Result = $IMAP->getquotaroot('user.joe.blah') || die "IMAP error: $@";
  $Result = {
    'quotaroot' => [
      'user.joe.blah', 'user.joe', ''
    ],
    'user.joe' => [
      'STORAGE', 31, 50000,
      'MESSAGES', 5, 1000
    ],
    '' => [
      'MESSAGES', 3498, 100000
    ]
  };

=cut
sub getquotaroot {
  my $Self = shift;
  $Self->_require_capability('quota') || return undef;
  return $Self->_imap_cmd("getquotaroot", 0, "quota", $Self->_fix_folder_name(+shift), @_);
}

=item I<message_count($FolderName)>

Return the number of messages in a folder. See also C<status()> for getting
more information about messages in a folder.

=cut
sub message_count {
  my $Self = shift;
  my $Res = $Self->status(+shift, '(messages)') || return undef;
  return $Res->{messages};
}

=item I<status($FolderName, $StatusList)>

Perform the standard IMAP 'status' command to retrieve status information about
a folder/mailbox.

The $StatusList is a bracketed list of folder items to obtain the status of.
Can contain: messages, recent, uidnext, uidvalidity, unseen.

The return value is a hash reference of lc(status-item) => value.

Examples:

  my $Res = $IMAP->status('inbox', '(MESSAGES UNSEEN)');

  $Res = {
    'messages' => 8,
    'unseen' => 2
  };

=cut
sub status {
  my $Self = shift;
  return $Self->_imap_cmd("status", 0, "status", $Self->_fix_folder_name(+shift), +shift);
}

=item I<multistatus($StatusList, @FolderNames)>

Performs many IMAP 'status' commands on a list of folders. Sends all the
commands at once and wait for responses. This speeds up latency issues.

Returns a hash ref of folder name => status results.

If an error occurs, the annotation result is a scalar ref to the completion
response string (eg 'bad', 'no', etc)

=cut
sub multistatus {
  my ($Self, $Items, @FolderList) = @_;

  # Send all commands at once
  my $CmdBuf = "";
  my $FirstId = $Self->{CmdId};
  $Items = ref($Items) ? $Self->_send_data({}, "", $Items) : " " . $Items;

  for (@FolderList) {
    $CmdBuf .= $Self->{CmdId}++ . " status " . ${_quote($Self->_fix_folder_name($_))} . $Items . LB;
  }
  $Self->_imap_socket_out($CmdBuf);

  # Parse responses
  my %Resp;
  $Self->{CmdId} = $FirstId;
  for (@FolderList) {
    my ($CompletionResp, $DataResp) = $Self->_parse_response("status");
    $Resp{$_} = ref($DataResp) ? $DataResp : \$CompletionResp;
    $Self->{CmdId}++;
  }

  return \%Resp;
}

=item I<getannotation($FolderName, $Entry, $Attribute)>

Perform the IMAP 'getannotation' command to get the annotation(s)
for a mailbox.  See imap-annotatemore extension for details.

Examples:

  my $Result = $IMAP->getannotation('user.joe.blah', '/*' '*') || die "IMAP error: $@";
  $Result = {
    'user.joe.blah' => {
      '/vendor/cmu/cyrus-imapd/size' => {
        'size.shared' => '5',
        'content-type.shared' => 'text/plain',
        'value.shared' => '19261'
      },
      '/vendor/cmu/cyrus-imapd/lastupdate' => {
        'size.shared' => '26',
        'content-type.shared' => 'text/plain',
        'value.shared' => '26-Mar-2004 13:31:56 -0800'
      },
      '/vendor/cmu/cyrus-imapd/partition' => {
        'size.shared' => '7',
        'content-type.shared' => 'text/plain',
        'value.shared' => 'default'
      }
    }
  };

=cut
sub getannotation {
  my $Self = shift;
  $Self->_require_capability('annotatemore') || return undef;
  return $Self->_imap_cmd("getannotation", 0, "annotation", $Self->_fix_folder_name(+shift, 1), { Quote => $_[0] }, { Quote => $_[1] });
}


=item I<getmetadata($FolderName, [ \%Options ], @Entries)>

Perform the IMAP 'getmetadata' command to get the metadata items
for a mailbox.  See RFC 5464 for details.

If $Options is passed, it is a hashref of options to set.

If foldername is the empty string, gets server annotations

Examples:

  my $Result = $IMAP->getmetadata('user.joe.blah', {depth => 'infinity'}, '/shared') || die "IMAP error: $@";
  $Result = {
    'user.joe.blah' => {
      '/shared/vendor/cmu/cyrus-imapd/size' => '19261',
      '/shared/vendor/cmu/cyrus-imapd/lastupdate' => '26-Mar-2004 13:31:56 -0800',
      '/shared/vendor/cmu/cyrus-imapd/partition' => 'default',
    }
  };

  my $Result = $IMAP->getmetadata('', "/shared/comment");
  $Result => {
    '' => {
      '/shared/comment' => "Shared comment",
    }
  };

=cut
sub getmetadata {
  my $Self = shift;
  $Self->_require_capability('metadata') || return undef;

  # First arg is folder name
  my @Args = $Self->_fix_folder_name(+shift, 0);
  # Next is optional hash of options
  push @Args, [%{ +shift }] if ref($_[0]) eq 'HASH';

  return $Self->_imap_cmd("getmetadata", 0, "metadata", @Args, { Quote => [ @_ ] });
}

=item I<setannotation($FolderName, $Entry, [ $Attribute, $Value ])>

Perform the IMAP 'setannotation' command to get the annotation(s)
for a mailbox.  See imap-annotatemore extension for details.

Examples:

  my $Result = $IMAP->setannotation('user.joe.blah', '/comment', [ 'value.priv' 'A comment' ])
    || die "IMAP error: $@";

=cut
sub setannotation {
  my $Self = shift;
  $Self->_require_capability('annotatemore') || return undef;
  return $Self->_imap_cmd("setannotation", 0, "annotation", $Self->_fix_folder_name(+shift, 1), { Quote => $_[0] }, { Quote => $_[1] });
}

=item I<setmetadata($FolderName, $Name, $Value, $Name2, $Value2)>

Perform the IMAP 'setmetadata' command.  See RFC 5464 for details.

Examples:

  my $Result = $IMAP->setmetadata('user.joe.blah', '/comment', 'A comment')
    || die "IMAP error: $@";

=cut
sub setmetadata {
  my $Self = shift;
  $Self->_require_capability('metadata') || return undef;
  return $Self->_imap_cmd("setmetadata", 0, "metadata", $Self->_fix_folder_name(+shift, 1), { Quote => [ @_ ] });
}

=item I<multigetannotation($Entry, $Attribute, @FolderNames)>

Performs many IMAP 'getannotation' commands on a list of folders. Sends
all the commands at once and wait for responses. This speeds up latency
issues.

Returns a hash ref of folder name => annotation results.

If an error occurs, the annotation result is a scalar ref to the completion
response string (eg 'bad', 'no', etc)

=cut
sub multigetannotation {
  my ($Self, $Entry, $Attribute, @FolderList) = @_;

  # Send all commands at once
  my $FirstId = $Self->{CmdId};
  for (@FolderList) {
    $Self->_send_cmd("getannotation", $Self->_fix_folder_name($_, 1), { Quote => $Entry }, { Quote => $Attribute });
    $Self->{CmdId}++;
  }

  # Parse responses
  my %Resp;
  $Self->{CmdId} = $FirstId;
  for (@FolderList) {
    my ($CompletionResp, $DataResp) = $Self->_parse_response("annotation");
    $Resp{$_} = ref($DataResp) ? $DataResp->{$_}->{$Entry}->{$Attribute} : \$CompletionResp;
    $Self->{CmdId}++;
  }

  return \%Resp;
}

=item I<close()>

Perform the standard IMAP 'close' command to expunge deleted messages
from the current folder and return to the Authenticated state.

=cut
sub close {
  my $Self = shift;
  $Self->_imap_cmd("close", 0, "", @_) || return undef;
  $Self->state(Authenticated);
}

=item I<idle(\&Callback, [ $Timeout ])>

Perform an IMAP idle call. Call given callback for each IDLE event
received.

If the callback returns 0, the idle continues. If the callback returns 1,
the idle is finished and this call returns.

If no timeout is passed, will continue to idle until the callback returns
1 or the server disconnects.

If a timeout is passed (including a 0 timeout), the call will return if
no events are received within the given time. It will return the result
of the DONE command, and set $Self->get_response_code('timeout') to true.

If the server closes the connection with a "bye" response, it will
return undef and $@ =~ /bye/ will be true with the remainder of the bye
line following.

=cut
sub idle {
  my ($Self, $Callback, $Timeout) = @_;

  # Create a closure to handle the idle semantics that runs
  #  between sending the command and parsing the tagged
  #  response (that only appears after sending DONE)
  my $PostCommand = sub {
    local $Self->{Timeout} = $Timeout if $Timeout;

    $Self->{ReadLine} = undef;

    my $Resp = $Self->_next_atom();
    my ($Text) = @{$Self->_remaining_atoms()};
    if (!$Resp || !$Text || $Resp ne '+' || $Text ne 'idling') {
      die "IMAPTalk: Did not get '+ idling' response";
    }

    # Special case 0 timeout
    if (defined $Timeout && $Timeout == 0) {
      $Self->{Cache}->{timeout} = 1;
      goto DoneIdle;
    }

    # If callback returns true, set $Exit to exit loop
    my $Exit = 0;
    my $WrapCallback = sub { $Exit = $Callback->(@_); };
    my %ParseCB = map { $_ => $WrapCallback } qw(exists recent expunge fetch);

    while (!$Exit) {
      eval {
        $Self->_parse_response(\%ParseCB, { IdleResponse => 1 });
      };
      if ($@) {
        if ($@ =~ /timed out/) {
          $Self->{Cache}->{timeout} = 1;
          goto DoneIdle;

        } elsif ($@ =~ /closed by host/) {
          die "IMAPTalk: bye: " . $Self->get_response_code('bye');

        } else {
          die $@;
        }
      }
    }

    # Send DONE, and then fallout to parse response
    DoneIdle:
    $Self->_imap_socket_out("DONE" . LB);
  };

  my %ParseMode = (PostCommand => $PostCommand);
  return $Self->_imap_cmd(\%ParseMode, 'idle', 0, '');
}


=back
=cut

=head1 IMAP MESSAGE COMMAND METHODS

=over 4
=cut

=item I<fetch([ \%ParseMode ], $MessageIds, $MessageItems)>

Perform the standard IMAP 'fetch' command to retrieve the specified message
items from the specified message IDs.

The first parameter can be an optional hash reference that overrides
particular parse mode parameters just for this fetch. See C<parse_mode>
for possible keys.

C<$MessageIds> can be one of two forms:

=over 4

=item 1.

A text string with a comma separated list of message ID's or message ranges
separated by colons. A '*' represents the highest message number.

Examples:

=over 4

=item * '1' - first message

=item * '1,2,5'

=item * '1:*' - all messages

=item * '1,3:*' - all but message 2

=back

Note that , separated lists and : separated ranges can be mixed, but to
make sure a certain hack works, if a '*' is used, it must be the last
character in the string.

=item 2.

An array reference with a list of message ID's or ranges. The array contents
are C<join(',', ...)>ed together.

=back

Note: If the C<uid()> state has been set to true, then all message ID's
must be message UIDs.

C<$MessageItems> can be one of, or a bracketed list of:

=over 4

=item * uid

=item * flags

=item * internaldate

=item * envelope

=item * bodystructure

=item * body

=item * body[section]<partial>

=item * body.peek[section]<partial>

=item * rfc822

=item * rfc822.header

=item * rfc822.size

=item * rfc822.text

=item * fast

=item * all

=item * full

=back

It would be a good idea to see RFC 3501 for what all these means.

Examples:

  my $Res = $IMAP->fetch('1:*', 'rfc822.size');
  my $Res = $IMAP->fetch([1,2,3], '(bodystructure envelope)');

Return results:

The results returned by the IMAP server are parsed into a Perl structure.
See the section B<FETCH RESULTS> for all the interesting details.

Note that message can disappear on you, so you may not get back
all the entries you expect in the hash

There is one piece of magic. If your request is for a single uid,
(eg "123"), and no data is return, we return undef, because it's
easier to handle as an error condition.

=cut
sub fetch {
  my $Self = shift;

  my $ParseMode = ref($_[0]) eq 'HASH' ? shift : {};

  # Are we fetching one uid
  my $FetchOne = !ref($_[0]) && $_[0] =~ /^\d+$/ && $_[0];

  # Clear any existing fetch responses and call the fetch command
  $Self->{Responses}->{fetch} = undef;
  my $FetchRes = $Self->_imap_cmd($ParseMode, "fetch", 1, "fetch", _fix_message_ids(+shift), @_);

  # Single message fetch with no data returns
  my $NoFetchData = ref($FetchRes) && !%$FetchRes;
  if ($NoFetchData && $FetchOne) {
    $Self->{LastError} = $@ = "Fetch of message uid $FetchOne failed. Message deleted by POP or other IMAP connection.";
    return undef;
  }

  # Multi message fetch with no data
  return {} if $NoFetchData;

  # Return data returned
  return $FetchRes;
}

=item I<copy($MsgIds, $ToFolder)>

Perform standard IMAP copy command to copy a set of messages from one folder
to another.

=cut
sub copy {
  my $Self = shift;
  my $Uids = _fix_message_ids(+shift);
  my $FolderName = $Self->_fix_folder_name(+shift);
  $Self->cb_folder_changed($FolderName);
  return $Self->_imap_cmd("copy", 1, "", $Uids, $FolderName, @_);
}

=item I<append($FolderName, optional $MsgFlags, optional $MsgDate, $MessageData)>

Perform standard IMAP append command to append a new message into a folder.

The $MessageData to append can either be a Perl scalar containing the data,
or a file handle to read the data from. In each case, the data must be in
proper RFC 822 format with \r\n line terminators.

Any optional fields not needed should be removed, not left blank.

Examples:

  # msg.txt should have \r\n line terminators
  open(F, "msg.txt");
  $IMAP->append('inbox', \*F);

  my $MsgTxt =<<MSG;
  From: blah\@xyz.com
  To: whoever\@whereever.com
  ...
  MSG

  $MsgTxt =~ s/\n/\015\012/g;
  $IMAP->append('inbox', { Literal => $MsgTxt });

=cut
sub append {
  my $Self = shift;
  my $FolderName = $Self->_fix_folder_name(+shift);
  $Self->cb_folder_changed($FolderName);
  return $Self->_imap_cmd("append", 0, "", $FolderName, @_);
}

=item I<search($MsgIdSet, @SearchCriteria)>

Perform standard IMAP search command. The result is an array reference to a list
of message IDs (or UIDs if in Uid mode) of messages that are in the $MsgIdSet
and also meet the search criteria.

@SearchCriteria is a list of search specifications, for example to look for
ASCII messages bigger than 2000 bytes you would set the list to be:

  my @SearchCriteria = ('CHARSET', 'US-ASCII', 'LARGER', '2000');

Examples:

  my $Res = $IMAP->search('1:*', 'NOT', 'DELETED');
  $Res = [ 1, 2, 5 ];

=cut
sub search {
  return (+shift)->_imap_cmd("search", 1, "search", _fix_message_ids(+shift), @_);
}

=item I<store($MsgIdSet, $FlagOperation, $Flags)>

Perform standard IMAP store command. Changes the flags associated with a
set of messages.

Examples:

  $IMAP->store('1:*', '+flags', '(\\deleted)');
  $IMAP->store('1:*', '-flags.silent', '(\\read)');

=cut
sub store {
  my $Self = shift;
  $Self->cb_folder_changed($Self->{CurrentFolder});
  return $Self->_imap_cmd("store", 1, "fetch", _fix_message_ids(+shift), @_);
}

=item I<expunge()>

Perform standard IMAP expunge command. This actually deletes any messages
marked as deleted.

=cut
sub expunge {
  my $Self = shift;
  $Self->cb_folder_changed($Self->{CurrentFolder});
  return $Self->_imap_cmd("expunge", 0, "", @_);
}

=item I<uidexpunge($MsgIdSet)>

Perform IMAP uid expunge command as per RFC 2359.

=cut
sub uidexpunge {
  my $Self = shift;
  $Self->cb_folder_changed($Self->{CurrentFolder});
  return $Self->_imap_cmd("uid expunge", 0, "", _fix_message_ids(+shift));
}

=item I<sort($SortField, $CharSet, @SearchCriteria)>

Perform extension IMAP sort command. The result is an array reference to a list
of message IDs (or UIDs if in Uid mode) in sorted order.

It would probably be a good idea to look at the sort RFC 5256 details at
somewhere like : http://www.ietf.org/rfc/rfc5256.txt

Examples:

  my $Res = $IMAP->sort('(subject)', 'US-ASCII', 'NOT', 'DELETED');
  $Res = [ 5, 2, 3, 1, 4 ];

=cut
sub sort {
  return (+shift)->_imap_cmd("sort", 1, "sort", @_);
}

=item I<thread($ThreadType, $CharSet, @SearchCriteria)>

Perform extension IMAP thread command. The $ThreadType should be one
of 'REFERENCES' or 'ORDEREDSUBJECT'. You should check the C<capability()>
of the server to see if it supports one or both of these.

Examples

  my $Res = $IMAP->thread('REFERENCES', 'US-ASCII', 'NOT', 'DELETED');
  $Res = [ [10, 15, 20], [11], [ [ 12, 16 ], [13, 17] ];

=cut
sub thread {
  return (+shift)->_imap_cmd("thread", 1, "thread", @_);
}

=item I<fetch_flags($MessageIds)>

Perform an IMAP 'fetch flags' command to retrieve the specified flags
for the specified messages.

This is just a special fast path version of C<fetch>.

=cut
sub fetch_flags {
  my $Self = shift;

  my $Cmd = $Self->{Uid} ? 'uid fetch' : 'fetch';
  $Self->_send_cmd($Cmd, _fix_message_ids(+shift), '(flags)');

  my $Tag = '';
  my ($MsgId, $Resp, %FetchRes);

  while (1) {
    local $_ = $Self->_imap_socket_read_line();

    ($Tag, $MsgId, $Resp, $_) = (/^(\S+) (\S+) (\S+)(?: \((.*)\))?/)
      or die "IMAPTalk: Expected tagged response, got $_";
    last if $Tag eq $Self->{CmdId};
    $Resp = lc $Resp;

    if ($Tag eq '*' and ($MsgId =~ m/\D/ or $UntaggedResponses{$Resp})) {
      # ignore untagged response
      next;
    }

    # only want FETCH responses
    if ($Resp eq 'fetch') {
      my ($Uid) = /UID (\d+)/i;
      my ($Flags) = /FLAGS \(([^)]*)\)/i;

      if (!defined $Uid || !defined $Flags) {
        $@ = "Unexpected response line. tag=$Tag, msgid=$MsgId, line=$_";
        return undef;
      }

      $FetchRes{$Uid} = { uid => $Uid, flags => [ split ' ', $Flags ] };

    # Unknown unexpected response line
    } else {
      $@ = "Unexpected response line. tag=$Tag, msgid=$MsgId, respond=$Resp, line=$_";
      return undef;
    }
  }

  return \%FetchRes;
}

=item I<fetch_meta($MessageIds, @MetaItems)>

Perform an IMAP 'fetch' command to retrieve the specified meta
items. These must be simple items that return only atoms
(eg no flags, bodystructure, body, envelope, etc)

This is just a special fast path version of C<fetch>.

=cut
sub fetch_meta {
  my $Self = shift;

  my $Cmd = $Self->{Uid} ? 'uid fetch' : 'fetch';
  $Self->_send_cmd($Cmd, _fix_message_ids(+shift), '(' . join(" ", @_) . ')');

  my $Tag = '';
  my ($MsgId, $Resp, %FetchRes);

  while (1) {
    local $_ = $Self->_imap_socket_read_line();

    ($Tag, $MsgId, $Resp, $_) = (/^(\S+) (\S+) (\S+)(?: \((.*)\))?/)
      or die "IMAPTalk: Expected tagged meta list, got $_";
    last if $Tag eq $Self->{CmdId};

    if ($Tag eq '*' and ($MsgId =~ m/\D/ or $UntaggedResponses{lc $Resp})) {
      # ignore untagged response
      next;
    }

    $_ = '' unless defined $_;

    # Fetch can always return flags result, need to handle that
    my %Items = /\bflags\b/i ? m{(\S+) ([^(]\S*|\([^)]*\)) ?}g : split(' ', $_);
    my $Uid = $Items{UID};

    unless (defined $Uid) {
      $@ = "Unexpected response line: $_";
      return undef;
    }

    $FetchRes{$Uid} = { map { lc($_) => $Items{$_} } keys %Items };
  }

  return \%FetchRes;
}

sub xmove {
  my $Self = shift;
  my $Uids = _fix_message_ids(+shift);
  my $FolderName = $Self->_fix_folder_name(+shift);
  $Self->cb_folder_changed($FolderName);
  return $Self->_imap_cmd("xmove", 1, "", $Uids, $FolderName, @_);
}

=back
=cut

=head1 IMAP CYRUS EXTENSION METHODS

Methods provided by extensions to the cyrus IMAP server

B<Note:> In all cases where a folder name is used, 
the folder name is first manipulated according to the current root folder
prefix as described in C<set_root_folder()>.

=over 4
=cut

=item I<xrunannotator($MessageIds)>

Run the xannotator command on the given message id's

=cut
sub xrunannotator {
  my $Self = shift;
  return $Self->_imap_cmd("xrunannotator", 1, "fetch", _fix_message_ids(+shift), @_);
}

=item I<xconvfetch($CIDs, $ChangedSince, $Items)>

Use the server XCONVFETCH command to fetch information about messages
in a conversation.

CIDs can be a single CID or an array ref of CIDs.

  my $Res = $IMAP->xconvfetch('2fc2122a109cb6c8', 0, '(uid cid envelope)')
  $Res = {
    state => { CID => [ HighestModSeq ], ... }
    folders => [ [ FolderName, UidValidity ], ..., ],
    found => [ [ FolderIndex, Uid, { Details } ], ... ],
  }

Note: FolderIndex is an integer index into the folders list

=cut
sub xconvfetch {
  my $Self = shift;
  my $CID = shift;

  my %Results;
  $Results{found} = \my @Fetch;
  $Results{folders} = \my @Folders;

  my %FolderMap;

  my %Callbacks = (
    xconvmeta => sub {
      my ($CID, $Data) = @{$_[1]};
      my $Res = _parse_list_to_hash($Data);
      $Results{state}{$CID} = [ $Res->{modseq} ];
    },

    fetch => sub {
      my (undef, $Fetch) = @_;
      my ($FolderName, $UidValidity, $Uid) = delete @$Fetch{qw(folder uidvalidity uid)};
      $FolderName = $Self->_unfix_folder_name($FolderName);
      if (!exists $FolderMap{$FolderName}) {
        my $FolderIndex = scalar @Folders;
        push @Folders, [ $FolderName, $UidValidity ];
        $FolderMap{$FolderName} = $FolderIndex;
      }
      push @Fetch, [ $FolderMap{$FolderName}, int($Uid), $Fetch ];
    }
  );

  $Self->_imap_cmd("xconvfetch", 0, \%Callbacks, $CID, @_)
    || return undef;

  return \%Results;
}

=item I<xconvmeta($CIDs, $Items)>

Use the server XCONVMETA command to fetch information about
a conversation.

CIDs can be a single CID or an array ref of CIDs.

  my $Res = $IMAP->xconvmeta('2fc2122a109cb6c8', '(senders exists unseen)')
  $Res = {
    CID1 => { senders => { name => ..., email => ... }, exists => ..., unseen => ..., ...  },
    CID2 => { ...  },
  }

=cut
sub xconvmeta {
  my ($Self, $CIDs, $Args) = @_;

  # Fix folder names in passed folderexists and folderunseen arguments
  $Self->_find_arg($Args, 'folderexists', sub { $_ = $Self->_fix_folder_name($_) for @$_; });
  $Self->_find_arg($Args, 'folderunseen', sub { $_ = $Self->_fix_folder_name($_) for @$_; });

  my %Results;

  my %Callbacks = (
    xconvmeta => sub {
      my (undef, $Data) = @_;
      my $Res = _parse_list_to_hash($Data->[1]);
      my %ResHash;
      foreach my $Item (keys %$Res) {
        if (lc($Item) eq 'senders') {
          $ResHash{senders} = [
            map {
              _decode_utf8($_->[0]) if defined $_->[0];
              {
               name => $_->[0],
               email => "$_->[2]\@$_->[3]",
              }
            } @{$Res->{$Item}} ];
        }
        elsif (lc($Item) eq 'count') {
          my %FolderCount = @{$Res->{$Item}};
          $ResHash{count} = { map {
             $Self->_unfix_folder_name($_) => int($FolderCount{$_})
          } keys %FolderCount };
        }
        elsif (lc($Item) eq 'folderexists') {
          my %FolderExists = @{$Res->{$Item}};
          $ResHash{folderexists} = { map { 
             $Self->_unfix_folder_name($_) => int($FolderExists{$_})
          } keys %FolderExists };
        }
        elsif (lc($Item) eq 'folderunseen') {
          my %FolderUnseen = @{$Res->{$Item}};
          $ResHash{folderunseen} = { map { 
             $Self->_unfix_folder_name($_) => int($FolderUnseen{$_})
          } keys %FolderUnseen };
        }
        else {
          $ResHash{lc($Item)} = int($Res->{$Item} // 0); # numeric
        }

      }
      $Results{$Data->[0]} = \%ResHash;
    },
  );

  $Self->_imap_cmd("xconvmeta", 0, \%Callbacks, $CIDs, $Args)
    || return undef;

  return \%Results;
}

=item I<xconvsort($Sort, $Window, $Charset, @SearchParams)>

Use the server XCONVSORT command to fetch exemplar conversation
messages in a mailbox.

  my $Res = $IMAP->xconvsort( [ qw(reverse arrival) ], [ 'conversations', position => [1, 10] ], 'utf-8', 'ALL')
  $Res = {
    sort => [ Uid, ... ],
    position => N,
    highestmodseq => M,
    uidvalidity => V,
    uidnext => U,
    total => R,
  }

=cut
sub xconvsort {
  my ($Self, $Sort, $Window, @Search) = @_;

  my %Callbacks = (responseitem => 'sort');
  my $Res = $Self->_imap_cmd("xconvsort", 0, \%Callbacks, $Sort, $Window, @Search)
    || return undef;

  my %Results;
  $Results{'sort'} = $Res if ref($Res);
  for (qw(position highestmodseq uidvalidity uidnext total)) {
    $Results{$_} = delete $Self->{Cache}->{$_};
  }

  return \%Results;
}

=item I<xconvupdates($Sort, $Window, $Charset, @SearchParams)>

Use the server XCONVUPDATES command to find changed exemplar
messages

  my $Res = $IMAP->xconvupdates( [ qw(reverse arrival) ], [ 'conversations', changedsince => [ $mod_seq, $uid_next ] ], 'utf-8', 'ALL');
  $Res = {
    added => [ [ Uid, Pos ], ... ],
    removed => [ Uid, ... ],
    changed => [ CID, ... ],
    highestmodseq => M,
    uidvalidity => V,
    uidnext => U,
    total => R,
  }

=cut
sub xconvupdates {
  my ($Self, $Sort, $Window, @Search) = @_;
 
  my %Results;

  my %Callbacks = (
    added => sub { $Results{added} = $_[1]; },
    removed => sub { $Results{removed} = $_[1]; },
    changed => sub { $Results{changed} = $_[1]; },
  );

  my $Res = $Self->_imap_cmd("xconvupdates", 0, \%Callbacks, $Sort, $Window, @Search)
    || return undef;

  for (qw(highestmodseq uidvalidity uidnext total)) {
    $Results{$_} = delete $Self->{Cache}->{$_};
  }

  return \%Results;
}

=item I<xconvmultisort($Sort, $Window, $Charset, @SearchParams)>

Use the server XCONVMULTISORT command to fetch messages across
all mailboxes

  my $Res = $IMAP->xconvmultisort( [ qw(reverse arrival) ], [ 'conversations', postion => [1,10] ], 'utf-8', 'ALL')
  $Res = {
    folders => [ [ FolderName, UidValidity ], ... ],
    sort => [ FolderIndex, Uid ], ... ],
    position => N,
    highestmodseq => M,
    total => R,
  }

Note: FolderIndex is an integer index into the folders list

=cut
sub xconvmultisort {
  my ($Self, $Sort, $Window, @Search) = @_;

  $Self->_find_arg(\@Search, 'folder', sub { $_ = $Self->_fix_folder_name($_) });
  $Self->_find_arg($Window, 'multianchor', sub { $_->[1] = $Self->_fix_folder_name($_->[1]) });

  my ($FolderList, $SortList);

  my %Callbacks = (xconvmulti => sub { ($FolderList, $SortList) = @{$_[1]}; });
  my $Res = $Self->_imap_cmd("xconvmultisort", 0, \%Callbacks, $Sort, $Window, @Search)
    || return undef;

  $_->[0] = $Self->_unfix_folder_name($_->[0]) for @$FolderList;

  my %Results;
  $Results{'folders'} = $FolderList;
  $Results{'sort'} = $SortList;
  for (qw(position highestmodseq total)) {
    $Results{$_} = delete $Self->{Cache}->{$_};
  }

  return \%Results;
}

=item I<xsnippets($Items, $Charset, @SearchParams)>

Use the server XSNIPPETS command to fetch message search snippets

  my $Res = $IMAP->xsnippets( [ [ FolderName, UidValidity, [ Uid, ... ] ], ... ], 'utf-8', 'ALL')
  $Res = {
    folders => [ [ FolderName, UidValidity ], ... ],
    snippets => [
      [ FolderIndex, Uid, Location, Snippet ],
      ...
    ]
  ]

Note: FolderIndex is an integer index into the folders list

=cut
sub xsnippets {
  my ($Self, $Items, @Search) = @_;

  $Self->_find_arg(\@Search, 'folder', sub { $_ = $Self->_fix_folder_name($_) });

  # Fix folder names passed in items argument
  $_->[0] = $Self->_fix_folder_name($_->[0]) for @$Items;

  my %Results;
  $Results{snippets} = \my @Snippets;
  $Results{folders} = \my @Folders;

  my %FolderMap;

  my %Callbacks = (snippet => sub {
    my ($FolderName, $UidValidity, $Uid, $Location, $Snippet) = @{$_[1]};
    $FolderName = $Self->_unfix_folder_name($FolderName);
    if (!exists $FolderMap{$FolderName}) {
      my $FolderIndex = scalar @Folders;
      push @Folders, [ $FolderName, $UidValidity ];
      $FolderMap{$FolderName} = $FolderIndex;
    }
    eval { $Snippet = decode_utf8($Snippet) };
    $Snippet =~ s/\x{fffd}//g; # Remove any bogus replacement chars, ugly display
    push @Snippets, [ $FolderMap{$FolderName}, int($Uid), $Location, $Snippet ];
  });

  my $Res = $Self->_imap_cmd("xsnippets", 0, \%Callbacks, $Items, @Search)
    || return undef;

  return \%Results;
}

sub xwarmup {
  my $Self = shift;
  $Self->_find_arg($_[1], 'uids', sub { $_ = _fix_message_ids($_) });
  return $Self->_imap_cmd("xwarmup", 0, "", $Self->_fix_folder_name(+shift), @_);
}

sub xmeid {
  my $Self = shift;
  my $XMEId = shift || '';
  return 1 if ($Self->{CurrentXMEId} || '') eq $XMEId;
  $Self->{CurrentXMEId} = $XMEId;
  return $Self->_imap_cmd('xmeid', 0, '', $XMEId);
}

=back
=cut

=head1 IMAP HELPER FUNCTIONS

=over 4
=cut

=item I<get_body_part($BodyStruct, $PartNum)>

This is a helper function that can be used to further parse the
results of a fetched bodystructure. Given a top level body
structure, and a part number, it returns the reference to
the bodystructure sub part which that part number refers to.

Examples:

  # Fetch body structure
  my $FR = $IMAP->fetch(1, 'bodystructure');
  my $BS = $FR->{1}->{bodystructure};

  # Parse further to find particular sub part
  my $P12 = $IMAP->get_body_part($BS, '1.2');
  $P12->{'IMAP->Partnum'} eq '1.2' || die "Unexpected IMAP part number";

=cut
sub get_body_part {
  my ($BS, $PartNum) = @_;

  my @PartNums = split(/\./, $PartNum);

  # This is a hack for special messages where the first entity
  #   is a message/rfc822 type. In which case, we have to strip
  #   the first item
  my $IsFirst = 1;

  while (1) {
    # Go no further if we found what we want
    return $BS
      if $BS->{'IMAP-Partnum'} eq $PartNum;

    # Has to have sub-parts, either mime-multipart or rfc822 sub-message
    return undef
      if (!$BS) ||
         (!@PartNums) ||
         (!exists $BS->{'MIME-Subparts'} &&
          !exists $BS->{'Message-Bodystructure'});

    # Get sub-part
    if (exists $BS->{'Message-Bodystructure'}) {
      $BS = $BS->{'Message-Bodystructure'};
      shift(@PartNums) if $IsFirst;
    }
    $BS = ($BS->{'MIME-Subparts'} || [])->[shift(@PartNums)-1] || $BS;
    $IsFirst = 0;
  }
}

=item I<find_message($BodyStruct)>

This is a helper function that can be used to further parse the results of
a fetched bodystructure. It returns a hash reference with the following
items.

  text => $best_text_part
  html => $best_html_part (optional)
  textlist => [ ... text/html (if no alt text bits)/image (if inline) parts ... ]
  htmllist => [ ... text (if no alt html bits)/html/image (if inline) parts ... ]
  att => [ {
     bs => $part, text => 0/1, html => 0/1, msg => 1/0,
   }, { ... }, ... ]

For instance, consider a message with text and html pages that's then
gone through a list software manager that attaches a header/footer

  multipart/mixed
    text/plain, cd=inline - A
    multipart/mixed
      multipart/alternative
        multipart/mixed
          text/plain, cd=inline - B
          image/jpeg, cd=inline - C
          text/plain, cd=inline - D
        multipart/related
          text/html - E
          image/jpeg - F
      image/jpeg, cd=attachment - G
      application/x-excel - H
      message/rfc822 - J
    text/plain, cd=inline - K

In this case, we'd have the following list items

  text => B
  html => E
  textlist => [ A, B, C, D, K ]
  htmllist => [ A, E, K ]
  att => [
    { bs => C, text => 1, html => 1 },
    { bs => F, text => 1, html => 0 },
    { bs => G, text => 1, html => 1 },
    { bs => H, text => 1, html => 1 },
    { bs => J, text => 0, html => 0, msg => 1 },
  ]

Examples:

  # Fetch body structure
  my $FR = $IMAP->fetch(1, 'bodystructure');
  my $BS = $FR->{1}->{bodystructure};

  # Parse further to find message components
  my $MC = $IMAP->find_message($BS);
  $MC = { 'plain' => ... text body struct ref part ...,
          'html' => ... html body struct ref part (if present) ... 
          'htmllist' => [ ... html body struct ref parts (if present) ... ] };

  # Now get the text part of the message
  my $MT = $IMAP->fetch(1, 'body[' . $MC->{text}->{'IMAP-Part'} . ']');

=cut
sub find_message {
  my (%MsgComponents);

  my %KnownTextParts = map { $_ => 1 } qw(plain html text enriched);

  my @PartList = ([ undef, $_[0], 0, '', \(my $Tmp = '') ]);

  # Repeat until we find something
  while (my $Part = shift @PartList) {
    my ($Parent, $BS, $Pos, $InMultiList, $MultiTypeRef) = @$Part;

    my $InsideAlt = $InMultiList =~ /\balternative\b/ ? 1 : 0;

    # Pull out common MIME fields we'll look at
    my ($MTT, $MT, $ST, $SP) = @$BS{qw(MIME-TxtType MIME-Type MIME-Subtype MIME-Subparts)};

    # Note: $DT can be "", which really is default "inline", so compare
    #  with "$DT ne 'attachment'", rather than "$DT eq 'inline'"
    my ($DT, $CD) = @$BS{qw(Disposition-Type Content-Disposition)};

    # Yay, found text component that ins't an attachment or has a filename
    if ($MT eq 'text' && ($DT ne 'attachment' && !$CD->{filename} && !$CD->{'filename*'})) {

      # See if it's a sub-type we understand/want
      if ($KnownTextParts{$ST}) {

        # Map plain, text, enriched -> text
        my $UT = $ST;
        $UT = 'text' if $ST eq 'plain' || $ST eq 'enriched';

        # Found it if not already found one of this type
        if ( !exists $MsgComponents{$UT} ) {

          # Don't treat html parts in a multipart/mixed as an
          #  alternative representation unless the first part
          if ( $ST eq 'html'
            && $Parent
            && $Parent->{'MIME-Subtype'} eq 'mixed'
            && $Pos > 0 )
          {
          }
          else {
            $MsgComponents{$UT} ||= $BS;
          }

        }

        # Override existing part if old part is <= 10 bytes (eg 5 blank
        # lines), and new part is > 10 bytes.  Or if old part has
        # 0 lines and new part has some lines
        elsif ( ( $MsgComponents{$UT}->{'Size'} <= 10 && $BS->{'Size'} > 10 )
          || ( $MsgComponents{$UT}->{Lines} < 1 && $BS->{Lines} > 0 ) )
        {
          $MsgComponents{$UT} = $BS;
        }

        # Add to textlist/htmllist if not in alternative part
        #  or best part type if we are
        if ($UT eq 'text' || !$InsideAlt) {
          push @{$MsgComponents{'textlist'}}, $BS;
          $$MultiTypeRef ||= $UT;
        }
        if ($UT eq 'html' || !$InsideAlt) {
          push @{$MsgComponents{'htmllist'}}, $BS;
          $$MultiTypeRef ||= $UT;
        }

        # Ok got a known part, move to next
        next;
      }
      # Wasn't a known text type, will add as an attachment

    } elsif ($MT eq 'image') {

      # Only add inline images
      if ($DT ne 'attachment') {
        # In alternative parts, we store which list part
        #  we're in in $InsideAlt
        my $ItemList = $MsgComponents{$$MultiTypeRef . 'list'};
        if ($ItemList) {
          push @$ItemList, $BS;
          # Mark this list as having an image
          $MsgComponents{$$MultiTypeRef . 'listimage'} = 1;
        }
      }
      # And always add the image as an attachment below

    # If it's a multi-part, what type
    } elsif ($MT eq 'multipart') {

      # Look at all sub-parts
      my $Pos = 0;
      my $MultiType = '';
      my $SubMultiList = join ",", ($InMultiList or ()), $ST;
      my @SubParts = map { [ $BS, $_, $Pos++, $SubMultiList, \$MultiType ] } @$SP;

      # If it's a signed/alternative/related sub-part, look in it FIRST
      if ($ST eq 'signed' || $ST eq 'alternative' || $ST eq 'related' || $DT ne 'attachment') {
        unshift @PartList, @SubParts;

      # Otherwise look in it after we've looked at all the other components
      #  at the current level
      } else {
        push @PartList, @SubParts;
      }

      # No attachment, move on to next part
      next;
    }

    # Pretty much everything goes in as an attachment, except images
    #  inside related parts
    push @{$MsgComponents{att}}, {
      bs => $BS,
      $MTT eq 'message/rfc822' ? (
        msg => 1
      ) : (
        text => 1,
        html => $MT eq 'image' && $InMultiList =~ /\brelated\b/ ? 0 : 1,
      )
    };
  }

  delete $MsgComponents{htmllist} if !$MsgComponents{html};

  return \%MsgComponents;
}

=item I<generate_cid( $Token, $PartBS )>

This method generates a ContentID based on $Token and $PartBS.

The same value should always be returned for a given $Token and $PartBS

=cut
sub generate_cid {

  my $Digester = Digest->new( 'MD5' );
  $Digester->add( $_[0] );
  $Digester->add( $_[1]->{'IMAP-Partnum'} || '' );
  $Digester->add( $_[1]->{'Size'} || 'none' );
  $Digester->add( $_[1]->{'MIME-TxtType'} || 'none' );
  my $Cid = 'generated-' . $Digester->hexdigest() . '@messagingengine.com';
  return $Cid;
}

=item I<build_cid_map($BodyStruct, [ $IMAP, $Uid, $GenCidToken ])>

This is a helper function that can be used to further parse the
results of a fetched bodystructure. It recursively parses the
bodystructure and returns a hash of Content-ID to bodystruct
part references. This is useful when trying to determine CID
links from an HTML message.

If you pass a Mail::IMAPTalk object as the second parameter,
the CID map built may be even more detailed. It seems some
stupid versions of exchange put details in the Content-Location
header rather than the Content-Type header. If that's the
case, this will try and fetch the header from the message

Examples:

  # Fetch body structure
  my $FR = $IMAP->fetch(1, 'bodystructure');
  my $BS = $FR->{1}->{bodystructure};

  # Parse further to get CID links
  my $CL = build_cid_map($BS);
  $CL = { '2958293123' => ... ref to body part ..., ... };

=cut
sub build_cid_map {
  my @PartStack = shift;
  my ($IMAP, $Uid, $GenCidToken) = @_;
  my %CIDHash;

  # While items left to process
  while (my $Part = shift @PartStack) {

    # For multi-part types, just add sub-parts to process stack
    if ($Part->{'MIME-Type'} eq 'multipart') {
      push @PartStack, @{$Part->{'MIME-Subparts'}};
    }

    # If content-id present
    my $CID = $Part->{'Content-ID'};
    if (! $CID) {
      $CID = generate_cid( $GenCidToken, $Part );
    }
    if ($CID) {
      # Strip any <> parts and add to hash
      $CID =~ s/^<(.*)>$/$1/;
      $CIDHash{$CID} = $Part

    }

    # If content-location present
    my $CLOC;
    if ($CLOC = $Part->{'Content-Location'}) {
      $CLOC =~ s/\s+//g;
      $CIDHash{$CLOC} ||= $Part;
    } elsif ($IMAP && $Uid) {
      # header.fields is only for rfc822 parts, have to get .MIME
      my $Headers = $IMAP->fetch($Uid, "body[" . $Part->{'IMAP-Partnum'} . ".MIME]");
      $Headers = $Headers->{$Uid}->{body} if $Headers;
      ($CLOC) = ($Headers =~ /^Content-Location: ([^\r\n]*(?:\r\n\s+[^\r\n]*)*)/m) if $Headers;
      $CLOC =~ s/\s+//g if $CLOC;
      $CIDHash{$CLOC} ||= $Part if $CLOC;
    }

    # Add content by name as well
    if (my $Name = $Part->{'Content-Type'}->{name}) {
      $CIDHash{$Name} ||= $Part;
    }

  }

  return \%CIDHash;
}

=item I<obliterate($CyrusName)>

Given a username (optionally username\@domain) immediately delete all messages belonging
to this user.  Uses LOCALDELETE.  Quite FastMail Patchd Cyrus specific.

=cut
sub obliterate {
  my $Self = shift;
  my $CyrusName = shift;

  # convert to bang notation
  my $basename = $CyrusName;
  my $domain;
  if ($basename =~ s{\@(.*)}{}) {
    $domain = $1;
  }

  my $folders = $Self->list($domain ? "$domain!user.$basename.*" : "user.$basename.*", "*");
  my $dfolders = $Self->list($domain ? "$domain!DELETED.user.$basename.*" : "DELETED.user.$basename.*", "*");
  $folders = [] unless ref($folders) eq 'ARRAY'; # stupid "completed" bug
  $dfolders = [] unless ref($dfolders) eq 'ARRAY'; # stupid "completed" bug

  my @list = reverse sort
             ($domain ? "$domain!user.$basename" : "user.$basename"),
             map { $_->[2] } @$folders, @$dfolders;

  foreach my $folder (@list) {
    $Self->localdelete($folder);
  }

  return 1;
}

=back
=cut

=head1 IMAP CALLBACKS

By default, these methods do nothing, but you can dervice
from Mail::IMAPTalk and override these methods to trap
any things you want to catch

=over 4
=cut

=item I<cb_switch_folder($CurrentFolder, $NewFolder)>

Called when the currently selected folder is being changed
(eg 'select' called and definitely a different folder
is being selected, or 'unselect' methods called)

=cut
sub cb_switch_folder { }

=item I<cb_folder_changed($Folder)>

Called when a command changes the contents of a folder
(eg copy, append, etc). $Folder is the name of the
folder that's changing.

=cut
sub cb_folder_changed { }

=back
=cut

=head1 FETCH RESULTS

The 'fetch' operation is probably the most common thing you'll do with an
IMAP connection. This operation allows you to retrieve information about a
message or set of messages, including header fields, flags or parts of the
message body.

C<Mail::IMAPTalk> will always parse the results of a fetch call into a Perl like
structure, though 'bodystructure', 'envelope' and 'uid' responses may
have additional parsing depending on the C<parse_mode> state and the C<uid>
state (see below).

For an example case, consider the following IMAP commands and responses
(C is what the client sends, S is the server response).

  C: a100 fetch 5,6 (flags rfc822.size uid)
  S: * 1 fetch (UID 1952 FLAGS (\recent \seen) RFC822.SIZE 1150)
  S: * 2 fetch (UID 1958 FLAGS (\recent) RFC822.SIZE 110)
  S: a100 OK Completed

The fetch command can be sent by calling:

  my $Res = $IMAP->fetch('1:*', '(flags rfc822.size uid)');

The result in response will look like this:

  $Res = {
    1 => {
      'uid' => 1952,
      'flags' => [ '\\recent', '\\seen' ],
      'rfc822.size' => 1150
    },
    2 => {
      'uid' => 1958,
      'flags' => [ '\\recent' ],
      'rfc822.size' => 110
    }
  };


A couple of points to note:

=over 

=item 1.

The message IDs have been turned into a hash from message ID to fetch
response result.

=item 2.

The response items (e.g. uid, flags, etc) have been turned into a hash for
each message, and also changed to lower case values.

=item 3.

Other bracketed (...) lists have become array references.

=back

In general, this is how all fetch responses are parsed.
There is one major difference however when the IMAP connection
is in 'uid' mode. In this case, the message IDs in the main hash are changed
to message UIDs, and the 'uid' entry in the inner hash is removed. So the
above example would become:

  my $Res = $IMAP->fetch('1:*', '(flags rfc822.size)');

  $Res = {
    1952 => {
      'flags' => [ '\\recent', '\\seen' ],
      'rfc822.size' => 1150
    },
    1958 => {
      'flags' => [ '\\recent' ],
      'rfc822.size' => 110
    }
  };

=head2 Bodystructure

When dealing with messages, we need to understand the MIME structure of
the message, so we can work out what is the text body, what is attachments,
etc. This is where the 'bodystructure' item from an IMAP server comes in.

  C: a101 fetch 1 (bodystructure)
  S: * 1 fetch (BODYSTRUCTURE ("TEXT" "PLAIN" NIL NIL NIL "QUOTED-PRINTABLE" 255 11 NIL ("INLINE" NIL) NIL))
  S: a101 OK Completed

The fetch command can be sent by calling:

  my $Res = $IMAP->fetch(1, 'bodystructure');

As expected, the resultant response would look like this:

  $Res = {
    1 => {
      'bodystructure' => [
        'TEXT', 'PLAIN', undef, undef, undef, 'QUOTED-PRINTABLE',
          255, 11, UNDEF, [ 'INLINE', undef ], undef
      ]
    }
  };

However, if you set the C<parse_mode(BodyStructure => 1)>, then the result would be:

  $Res = {
    '1' => {
      'bodystructure' => {
        'MIME-Type' => 'text',
        'MIME-Subtype' => 'plain',
        'MIME-TxtType' => 'text/plain',
        'Content-Type' => {},
        'Content-ID' => undef,
        'Content-Description' => undef,
        'Content-Transfer-Encoding' => 'QUOTED-PRINTABLE',
        'Size' => '3569',
        'Lines' => '94',
        'Content-MD5' => undef,
        'Disposition-Type' => 'inline',
        'Content-Disposition' => {},
        'Content-Language' => undef,
        'Remainder' => [],
        'IMAP-Partnum' => ''
      }
    }
  };

A couple of points to note here:

=over 4

=item 1.

All the positional fields from the bodystructure list response
have been turned into nicely named key/value hash items.

=item 2.

The MIME-Type and MIME-Subtype fields have been made lower case.

=item 3.

An IMAP-Partnum item has been added. The value in this field can
be passed as the 'section' number of an IMAP body fetch call to
retrieve the text of that IMAP section.

=back

In general, the following items are defined for all body structures:

=over 4

=item * MIME-Type

=item * MIME-Subtype

=item * Content-Type

=item * Disposition-Type

=item * Content-Disposition

=item * Content-Language

=back

For all bodystructures EXCEPT those that have a MIME-Type of 'multipart',
the following are defined:

=over 4

=item * Content-ID

=item * Content-Description

=item * Content-Transfer-Encoding

=item * Size

=item * Content-MD5

=item * Remainder

=item * IMAP-Partnum

=back

For bodystructures where MIME-Type is 'text', an extra item 'Lines'
is defined.

For bodystructures where MIME-Type is 'message' and MIME-Subtype is 'rfc822', the
extra items 'Message-Envelope', 'Message-Bodystructure' and 'Message-Lines'
are defined. The 'Message-Bodystructure' item is itself a reference
to an entire bodystructure hash with all the format information of the
contained message. The 'Message-Envelope' item is a hash structure with
the message header information. See the B<Envelope> entry below.

For bodystructures where MIME-Type is 'multipart', an extra item 'MIME-Subparts' is
defined. The 'MIME-Subparts' item is an array reference, with each item being a
reference to an entire bodystructure hash with all the format information
of each MIME sub-part.

For further processing, you can use the B<find_message()> function.
This will analyse the body structure and find which part corresponds
to the main text/html message parts to display. You can also use
the B<find_cid_parts()> function to find CID links in an html
message.

=head2 Envelope

The envelope structure contains most of the addressing header fields from
an email message. The following shows an example envelope fetch (the
response from the IMAP server has been neatened up here)

  C: a102 fetch 1 (envelope)
  S: * 1 FETCH (ENVELOPE
      ("Tue, 7 Nov 2000 08:31:21 UT"      # Date
       "FW: another question"             # Subject
       (("John B" NIL "jb" "abc.com"))    # From
       (("John B" NIL "jb" "abc.com"))    # Sender
       (("John B" NIL "jb" "abc.com"))    # Reply-To
       (("Bob H" NIL "bh" "xyz.com")      # To
        ("K Jones" NIL "kj" "lmn.com"))
       NIL                                # Cc
       NIL                                # Bcc
       NIL                                # In-Reply-To
       NIL)                               # Message-ID
     )
  S: a102 OK Completed

The fetch command can be sent by calling:

  my $Res = $IMAP->fetch(1, 'envelope');

And you get the idea of what the resultant response would be. Again
if you change C<parse_mode(Envelope => 1)>, you get a neat structure as follows:

  $Res = {
    '1' => {
      'envelope' => {
        'Date' => 'Tue, 7 Nov 2000 08:31:21 UT',
        'Subject' => 'FW: another question',
        'From' => '"John B" <jb@abc.com>',
        'Sender' => '"John B" <jb@abc.com>',
        'Reply-To' => '"John B" <jb@abc.com>',
        'To' => '"Bob H" <bh@xyz.com>, "K Jones" <kj@lmn.com>',
        'Cc' => '',
        'Bcc' => '',
        'In-Reply-To' => undef,
        'Message-ID' => undef,

        'From-Raw' => [ [ 'John B', undef, 'jb', 'abc.com' ] ],
        'Sender-Raw' => [ [ 'John B', undef, 'jb', 'abc.com' ] ],
        'Reply-To-Raw' => [ [ 'John B', undef, 'jb', 'abc.com' ] ],
        'To-Raw' => [
          [ 'Bob H', undef, 'bh', 'xyz.com' ],
          [ 'K Jones', undef, 'kj', 'lmn.com' ],
        ],
        'Cc-Raw' => [],
        'Bcc-Raw' => [],
      }
    }
  };

All the fields here are from straight from the email headers.
See RFC 822 for more details.

=head2 Annotation

If the server supports RFC 5257 (ANNOTATE Extension), then you can
fetch per-message annotations.

Annotation responses would normally be returned as a a nested set of
arrays. However it's much easier to access the results as a nested set
of hashes, so the results are so converted if the Annotation parse
mode is enabled, which is on by default.

Part of an example from the RFC

   S: * 12 FETCH (UID 1123 ANNOTATION
      (/comment (value.priv "My comment"
         size.priv "10")
      /altsubject (value.priv "Rhinoceroses!"
         size.priv "13")

So the fetch command:

  my $Res = $IMAP->fetch(1123, 'annotation', [ '/*', [ 'value.priv', 'size.priv' ] ]);

Would have the result:

  $Res = {
    '1123' => {
      'annotation' => {
        '/comment' => {
          'value.priv' => 'My comment',
          'size.priv => 10
        },
        '/altsubject' => {
          'value.priv' => '"Rhinoceroses',
          'size.priv => 13
        }
      }
    }
  }
         
=cut

=head1 INTERNAL METHODS

=over 4
=cut

=item I<_imap_cmd($Command, $IsUidCmd, $RespItems, @Args)>

Executes a standard IMAP command.

=item I<Method arguments>

=over 4

=item B<$Command>

Text string of command to call IMAP server with (e.g. 'select', 'search', etc).

=item B<$IsUidCmd>

1 if command involved message ids and can be prefixed with UID, 0 otherwise.

=item B<$RespItems>

Responses to look for from command (eg 'list', 'fetch', etc). Commands
which return results usually return them untagged. The following is an
example of fetching flags from a number of messages.

  C123 uid fetch 1:* (flags)
  * 1 FETCH (FLAGS (\Seen) UID 1)
  * 2 FETCH (FLAGS (\Seen) UID 2)
  C123 OK Completed

Between the sending of the command and the 'OK Completed' response,
we have to pick up all the untagged 'FETCH' response items so we
would pass 'fetch' (always use lower case) as the $RespItems to extract.

This can also be a hash ref of callback functions. See _parse_response
for more examples

=item B<@Args>

Any extra arguments to pass to command.

=back

=cut
sub _imap_cmd {
  my $Self = shift;
  my $ParseMode = ref($_[0]) eq 'HASH' ? shift : {};
  my ($Cmd, $IsUidCmd, $RespItems) = (shift, shift, shift);

  # Remember the last command and reset last error
  $Self->{LastCmd} = $Cmd;
  $Self->{LastError} = undef;

  # Prefix command with uid if uid command and in uid mode
  $Cmd = 'uid ' . $Cmd if $IsUidCmd && $Self->{Uid};

  # Send command and parse response. Put in an eval because we 'die' if any problems
  my ($CompletionResp, $DataResp);
  eval {
    # Send the command and parse the response
    $Self->_send_cmd($Cmd, @_);
    $ParseMode->{PostCommand}->() if $ParseMode->{PostCommand};
    # Items returned are the complete response (eg ok/bad/no) and
    #  the any parsed data to return from the command
    ($CompletionResp, $DataResp) = $Self->_parse_response($RespItems, $ParseMode);
  };
  $Self->{CmdId}++;
  $Self->{LastRespCode} = $CompletionResp;

  # Return undef if any error occurred (either through 'die' or non-'OK' IMAP response)
  if ($@) {
    warn($@) if $@ !~ /NO Over quota/;

    # One of our errors? Capture, set $@ and return undef
    if ($@ =~ /IMAPTalk/ && !$Self->{Pedantic}) {
      $Self->{LastError} = $@ = "IMAP Command : '$Cmd' failed. Reason was : $@";
      return undef;
    }

    # If something else threw the error, rethrow, but release socket first since
    #  connection is in an indeterminate state
    $Self->release_socket(1);
    die $@;
  };

  if ($CompletionResp !~ /^ok/) {
    $Self->{LastError} = $@ = "IMAP Command : '$Cmd' failed. Response was : $CompletionResp - $DataResp";
    return undef;
  }

  # If we want an array response, handle undef and array ref cases specially
  if (wantarray) {
    # If undef response, return empty array
    return () if !defined($DataResp);
    # If respose is array reference, return array
    return @$DataResp if ref($DataResp) eq "ARRAY";
  }

  # Otherwise return response as single item
  return $DataResp;
}

=item I<_send_cmd($Self, $Cmd, @InArgs)>

Helper method used by the B<_imap_cmd> method to actually build (and
quote where necessary) the command arguments and then send the
actual command.

=cut
sub _send_cmd {
  my ($Self, $Cmd) = (shift, shift);

  # Send command. Build line buffer of args
  my $LineBuffer = $Self->{CmdId} . " " . $Cmd;
  $LineBuffer = $Self->_send_data({}, $LineBuffer, @_);

  # Output remainder of line buffer (if empty, we still want
  #  to send the \015\012 chars)
  $Self->_imap_socket_out($LineBuffer . LB) if defined $LineBuffer;

  return 1;
}

=item I<_send_data($Self, $Opts, $Buffer, @Args)>

Helper method used by the B<_send_cmd> method to actually build (and
quote where necessary) the command arguments and then send the
actual command.

=cut
sub _send_data {
  my ($Self, $Opts, $LineBuffer, @Args) = @_;

  my ($AddSpace, $NextAddSpace) = (1, 1);
  foreach my $Arg (@Args) {
    my ($IsQuote, $IsLiteral, $IsFile) = ($Opts->{Quote}, 0, 0);

    # --- Determine value type and appropriate output

    # Map undef to NIL atom
    if (!defined($Arg)) {
      $Arg = "NIL";
      $IsQuote = 0;

    # If it's a reference, then must be a file, scalar or hash ref
    } elsif (ref($Arg)) {

      # Hash refs are used to encode special handling of items
      if (ref($Arg) eq "HASH") {
        if (exists $Arg->{Quote}) {
          $IsQuote = 1;
          $Arg = $Arg->{Quote};
        } elsif (exists $Arg->{Literal}) {
          $IsLiteral = 1;
          $Arg = ref($Arg->{Literal}) ?  $Arg->{Literal} : \$Arg->{Literal};
        } elsif (exists $Arg->{Raw}) {
          $AddSpace = !$Arg->{NoSpace};
          $NextAddSpace = !$Arg->{NoNextSpace};
          $IsQuote = 0;
          $Arg = $Arg->{Raw};
        } else {
          die "Unknown hash arg type: " . (keys %$Arg)[0];
        }
      }

      # Above may have changed $Arg, so not an elsif here

      if (ref($Arg)) {
        # Array reference, wrap in ()'s
        if (ref($Arg) eq "ARRAY") {
          $LineBuffer = $Self->_send_data(
            { Quote => $IsQuote },
            $LineBuffer,
            { NoSpace => !$AddSpace, Raw => "(", NoNextSpace => 1 },
            @$Arg,
            { NoSpace => 1, Raw => ")", NoNextSpace => 1 }
          );
          next;

        # If it's a scalar ref, just use value it references
        } elsif (ref($Arg) eq "SCALAR") {

        # If it's a hash ref, deal with
        # Must be a file ref
        } elsif (UNIVERSAL::isa($Arg, "GLOB")) {
          $IsLiteral = $IsFile = 1;

        } else {
          die "Unknown reference arg type: " . ref($Arg);
        }
      }

    # If it's got a \000 or \012 or \015, we need to make it a literal.
    } elsif ($Arg =~ m/[\000\012\015]/) {
      $IsLiteral = 1;

    # If it's got other invalid chars, but doesn't start with a "(",
    # just quote it
    } elsif ($Arg =~ m/[\000-\040\{\} \%\*\"\(\)]/ && !($Arg =~ m/^\(/)) {
      $IsQuote = 1;

    # Empty string, send empty quotes
    } elsif ($Arg eq "") {
      $IsQuote = 1;

    # Otherwise leave as normal
    } else {
    }

    # --- Deal with outputing value

    # Handle non-literals
    if (!$IsLiteral) {
      $Arg = _quote(ref($Arg) ? $$Arg : $Arg) if $IsQuote;
      
      # Must be a scalar reference for a non-literal
      $LineBuffer .= ($AddSpace ? " " : "") . (ref($Arg) ? $$Arg : $Arg);

    # It's a literal, has to be scalar, scalar ref or file ref
    } else {
      # Get the size of the literal
      my $LiteralSize = 0;

      if (!$IsFile) {
        $LiteralSize = ref($Arg) ? length($$Arg) : length($Arg);

      # Otherwise it's a file ref
      } else {
        seek($Arg, 0, 2); # SEEK_END
        $LiteralSize = tell($Arg);
        seek($Arg, 0, 0); # SEEK_SET
      }

      # Add to line buffer and send
      $LineBuffer .= ($AddSpace ? " " : "") . "{" . $LiteralSize . "}" . LB;
      $Self->_imap_socket_out($LineBuffer);

      $LineBuffer = "";

      # Wait for "+ go ahead" response
      my $GoAhead = $Self->_imap_socket_read_line();
      if ($GoAhead =~ /^\+/) {
        if (!$IsFile) {
          $Self->_imap_socket_out(ref($Arg) ? $$Arg : $Arg);
        } else {
          $Self->_copy_handle_to_handle($Arg, $Self->{Socket}, $LiteralSize);
        }

      # If no "+ go ahead" response, stick back in read buffer and fall out
      #  to parse what the response was
      } else {
        substr($Self->{ReadBuf}, 0, 0, $GoAhead . LB);
        return undef;
      }

    }
    $AddSpace = $NextAddSpace;
    $NextAddSpace = 1;
  }

  return $LineBuffer;
}

=item I<_parse_response($Self, $RespItems, [ \%ParseMode ])>

Helper method called by B<_imap_cmd> after sending the command. This
methods retrieves data from the IMAP socket and parses it into Perl
structures and returns the results.

$RespItems is either a string, which is the untagged response(s)
to find and return, or for custom processing, it can be a
hash ref.

If a hash ref, then each key will be an untagged response to look for,
and each value a callback function to call for the corresponding untagged
response.

Each callback will be called with 2 or 3 arguments; the untagged
response string, the remainder of the line parsed into an array ref, and
for fetch type responses, the id will be passed as the third argument.

One other piece of magic, if you pass a 'responseitem' key, then the
value should be a string, and will be the untagged response returned
from the function

=cut
sub _parse_response {
  my ($Self, $RespItems, $ParseMode) = @_;

  # Loop until we get the tagged response for the sent command
  my $Result;
  my $Tag = '';
  my (%DataResp, $CompletionResp, $Res1, $Callback, %UnfixCache);

  # Build final parse mode. Note overrides come second to replace defaults
  my %ParseMode = (%{$Self->{ParseMode} || {}}, %{$ParseMode || {}});

  # Some commands might have no results (eg list, fetch, etc), but we
  #  want to distinguish no results vs IMAP NO result, so setup a default
  #  empty hash/array for these commands as appropriate.
  #  Create empty hash/array, don't copy ref to global!
  if (!ref($RespItems) && (my $RespDefault = $RespDefaults{$RespItems})) {
    $DataResp{$RespItems} = {} if $RespDefault eq 'hash';
    $DataResp{$RespItems} = [] if $RespDefault eq 'array';
  }

  # Response item we'll return
  my $RespItem = !ref($RespItems) ? $RespItems : $RespItems->{responseitem} || '';

  # Store completion response and data responses
  while ($Tag ne $Self->{CmdId}) {
    if ($Tag && $Tag ne '*' && $Self->{Pedantic}) {
      die "IMAPTalk: Unexpected tag '$Tag'";
    }

    # Force starting new line read
    $Self->{ReadLine} = undef;

    # Get next response id and response item type
    $Tag = $Self->_next_simple_atom();
    $Res1 = $CompletionResp = lc($Self->_next_simple_atom());

    # This is a big switch that works out what to do with each result type

    # If it's a number, we're getting some info about a message
    RepeatSwitch:
    if ($Res1 =~ /^(\d+)$/) {

      my $Res2 = lc($Self->_next_simple_atom());

      # Parse fetch response into perl structure
      my $Fetch;
      if ($Res2 eq 'fetch') {
        $Fetch = _parse_fetch_result($Self->_next_atom(), \%ParseMode);
      }

      if (ref($RespItems) && ($Callback = $RespItems->{$Res2})) {
        $Callback->($Res2, $Fetch || $Res1, $Res1);

      } elsif ($Res2 eq 'exists' || $Res2 eq 'recent' || $Res2 eq 'expunge') {
        $DataResp{$Res2} = $Res1;

      } elsif ($Res2 eq 'fetch') {
        # If UID mode, and got fetch result, transform from ID -> UID hash
        $Res1 = $Fetch->{uid} if $Self->{Uid};
        $Res1 ||= '';
        # Store the result in our response hash
        my $FetchRes = ($DataResp{fetch}->{$Res1} ||= {});
        %$FetchRes = (%$FetchRes, %$Fetch);

      } else {
        # Don't know other response types, just store the atom
        $DataResp{$Res2} = $Self->_next_atom();
      }

    } elsif (ref($RespItems) && ($Callback = $RespItems->{$Res1})) {
       $Callback->($Res1, $Self->_remaining_atoms($Res1 =~ /sort/ ? 1 : 0));

    } elsif ($Res1 eq 'ok') {
      # If OK, probably something like * OK [... ]
      my $Line = $DataResp{remainder} = $Self->_remaining_line();

      # Extract items inside [...]
      if ($Line =~ /\[(.*)\] ?(.*)$/) {
        $Self->{ReadLine} = $1;
        $DataResp{remainder} = $2;

        # Use atom parser to get internal items (ignore errors)
        $Res1 = eval { lc($Self->_next_atom()) };
        goto RepeatSwitch if defined $Res1;

        # Error case, empty any buffer and keep going
        $Self->{ReadLine} = '';
      }

    } elsif ($Res1 eq 'search' || $Res1 eq 'sort') {
      my $IdList = $Self->_remaining_atoms(1);

      # AOL server returns multiple SEARCH responses
      if (ref($DataResp{$Res1}) eq 'ARRAY') {
        push @{$DataResp{$Res1}}, @$IdList;
      } else {
        # Avoid data copy if possible, could be large UID list
        $DataResp{$Res1} = $IdList;
      }
    } elsif ($Res1 eq 'status') {
      my ($Name, $StatusRes) = @{$Self->_remaining_atoms()};
      $StatusRes = _parse_list_to_hash($StatusRes);

      # If we explicit requested parsing the status response, we just want
      #  the data (we know the folder). Otherwise this is an unsolicited
      #  status response (eg list extended return status), and we want
      #  to store the folder so we can get it via get_response_code.
      if ($RespItem eq 'status') {
        $DataResp{$Res1} = $StatusRes;
      } else {
        $Name = ($UnfixCache{$Name} ||= $Self->_unfix_folder_name($Name));
        $DataResp{$Res1}->{$Name} = $StatusRes;
      }

    } elsif ($Res1 eq 'flags' || $Res1 eq 'thread' || $Res1 eq 'namespace' || $Res1 eq 'myrights') {
      $DataResp{$Res1} = $Self->_remaining_atoms();

    } elsif ($Res1 eq 'xlist' || $Res1 eq 'list' || $Res1 eq 'lsub') {
      my ($Attr, $Sep, $Name) = @{$Self->_remaining_atoms()};
      $Self->_set_separator($Sep);
      # Remove root text from folder name
      $Name = ($UnfixCache{$Name} ||= $Self->_unfix_folder_name($Name));
      push @{$DataResp{$Res1}}, [ $Attr, $Sep, $Name ];
    } elsif ($Res1 eq 'permanentflags' || $Res1 eq 'uidvalidity' ||
      $Res1 eq 'uidnext' || $Res1 eq 'highestmodseq' || $Res1 eq 'numresults') {
      $DataResp{$Res1} = $Self->_next_atom();
      $Self->_remaining_line();

    } elsif ($Res1 eq 'newname' ||
      $Res1 eq 'parse' || $Res1 eq 'trycreate') {
      $DataResp{$Res1} = $Self->_remaining_line();

    } elsif ($Res1 eq 'alert') {
      # No argument to alert, it's the remainder of the line after the ]
      $DataResp{$Res1} = delete $DataResp{remainder};

    } elsif ($Res1 eq 'capability' || $Res1 eq 'enabled') {
      $DataResp{$Res1} = { map { lc($_) => 1 } @{$Self->_remaining_atoms() || []} };

    } elsif ($Res1 eq 'vanished') {
      $DataResp{$Res1} = $Self->_remaining_atoms();

    } elsif ($Res1 eq 'appenduid') {
      $DataResp{$Res1} = [ $Self->_next_atom(), $Self->_next_atom() ];
      $Self->_remaining_line();

    } elsif ($Res1 eq 'copyuid') {
      $DataResp{$Res1} = [ $Self->_next_atom(), $Self->_next_atom(), $Self->_next_atom() ];
      $Self->_remaining_line();

    } elsif ($Res1 eq 'read-write' || $Res1 eq 'read-only') {
      $DataResp{$Res1} = 1;
      $DataResp{foldermode} = $Res1;
      $Self->_remaining_line();

    } elsif ($Res1 eq 'quota') {
      # Result is: foldername (limits triplets)
      # If just a 'getquota', just return triplets. If a 'getrootquota',
      #  build the hash response
      my ($qfolder, $qlimits) = ($Self->_next_atom(), $Self->_next_atom());
      if (ref($DataResp{$Res1})) {
        $DataResp{$Res1}->{$qfolder} = $qlimits;
      } else {
        $DataResp{$Res1} = $qlimits;
      }

    } elsif ($Res1 eq 'quotaroot') {
      # Result is: foldername rootitems
      $DataResp{quota} = { 'quotaroot' => $Self->_remaining_atoms() };

    } elsif ($Res1 eq 'acl') {
      $DataResp{acl} = $Self->_remaining_atoms();
      shift @{$DataResp{acl}};

    } elsif ($Res1 eq 'annotation') {
      my ($Name, $Entry, $Attributes) = @{$Self->_remaining_atoms()};
      $Name = ($UnfixCache{$Name} ||= $Self->_unfix_folder_name($Name));
      $DataResp{annotation}->{$Name}->{$Entry} = { @{$Attributes || []} };

    } elsif ($Res1 eq 'metadata') {
      my ($Name, $Bits) = @{$Self->_remaining_atoms()};
      $Name = ($UnfixCache{$Name} ||= $Self->_unfix_folder_name($Name));
      $DataResp{metadata}->{$Name}->{$Bits->[0]} = $Bits->[1];

    } elsif (($Res1 eq 'bye') && ($Self->{LastCmd} ne 'logout')) {
      $Self->{Cache}->{bye} = $Self->_remaining_line();
      die "IMAPTalk: Connection was unexpectedly closed by host";

    } elsif ($Res1 eq 'no' || $Res1 eq 'bad') {
      $Result = $Self->_remaining_line();

    } else {
      $DataResp{$Res1} = $Self->_remaining_line();
    }

    # Should have read all of line
    if ($Self->{ReadLine} ne '') {
      die 'IMAPTalk: Unexpected data remaining on response line "' . $Self->{ReadLine} . '"';
    }

    last if $ParseMode{IdleResponse};
  }

  # Return the requested item from %DataResp, and put
  #  the rest in $Self->{Cache}
  $Result ||= delete $DataResp{$RespItem};
  $Result ||= $Res1;
  $Self->{Cache}->{$_} = $DataResp{$_} for keys %DataResp;

  return ($CompletionResp, $Result);
}

=item I<_require_capability($Self, $Capability)>

Helper method which checks that the server has a certain capability.
If not, it sets the internal last error, $@ and returns undef.

=cut
sub _require_capability {
  my ($Self, $Capability) = @_;
  my $Caps = $Self->capability() || {};
  if (!exists $Caps->{$Capability}) {
    $Self->{LastError} = $@ = "IMAP server has no $Capability capability";
    return undef;
  }
  return 1;
}

=item I<_trace($Self, $Line)>

Helper method which outputs any tracing data.

=cut
sub _trace {
  my ($Self, $Line) = @_;
  $Line =~ s/\015\012/\n/;
  my $Trace = $Self->{Trace};
  
  if (ref($Trace) eq 'GLOB') {
    print $Trace $Line;
  } elsif (ref($Trace) eq 'CODE') {
    $Trace->($Line);
  } elsif (ref($Trace) eq 'SCALAR') {
    $$Trace ||= '';
    $$Trace .= $Line;
  } elsif ($Trace == 1) {
    print STDERR $Line;
  }
}

=item I<_is_current_folder($Self, $FolderName)>

Return true if a folder is currently selected and that
folder is $FolderName

=cut
sub _is_current_folder {
  my ($Self, $Folder) = @_;

  return ($Self->state() == Selected) &&
         ($Folder eq $Self->{CurrentFolder});
}

=back
=cut

=head1 INTERNAL SOCKET FUNCTIONS

=over 4
=cut

=item I<_next_atom($Self)>

Returns the next atom from the current line. Uses $Self->{ReadLine} for
line data, or if undef, fills it with a new line of data from the IMAP
connection socket and then begins processing.

If the next atom is:

=over 4

=item *

An unquoted string, simply returns the string.

=item *

A quoted string, unquotes the string, changes any occurances
of \" to " and returns the string.

=item *

A literal (e.g. {NBytes}\r\n), reads the number of bytes of data
in the literal into a scalar or file (depending on C<literal_handle_control>).

=item *

A bracketed structure, reads all the sub-atoms within the structure
and returns an array reference with all the sub-atoms.

=back

In each case, after parsing the atom, it removes any trailing space separator,
and then returns the remainder of the line to $Self->{ReadLine} ready for the
next call to C<_next_atom()>.

=cut
sub _next_atom {
  my ($Self, $Atom, $CurAtom, @AtomStack) = (+shift, undef, undef);
  my ($Line, $AtomRef) = ($Self->{ReadLine}, \$Atom);

  # Fill line buffer if nothing left
  $Line = $Self->_imap_socket_read_line() if !defined $Line;

  # While this is a recursive structure, doing some profiling showed
  #  that this call was taking up quite a bit of time in the application
  #  I was using this module with. Thus I've tried to optimise the code
  #  a bit by turning it into a loop with an explicit stack and keeping
  #  the most common cases quick.

  # Always do this once, and keep doing it while we're within
  #   a bracketed list of items
  do {

    # Single item? (and any trailing space)
    # (make it trailing spaces, due to buggy XIMAPPROXY)
    if ($Line =~ m/\G([^()\"{\s]+)(?: +|\z|(?=\)))/gc) {
      # Add to current atom. If there's a stack, must be within a bracket
      if (scalar @AtomStack) {
        push @$AtomRef, $1 eq 'NIL' ? undef : $1;
      } else {
        $$AtomRef = $1 eq 'NIL' ? undef : $1;
      }
    }

    # Quoted section? (but non \" end quote and any trailing space)
    elsif ($Line =~ m/\G"((?:\\.|[^"])*?)"(?: |\z|(?=\)))/gc) {
      # Unquote quoted items
      ($CurAtom = $1) =~ s/\\(.)/$1/g;
      # Add to current atom. If there's a stack, must be within a bracket
      if (scalar @AtomStack) {
        push @$AtomRef, $CurAtom;
      } else {
        $$AtomRef = $CurAtom;
      }
    }
    
    # Bracket?
    elsif ($Line =~ m/\G\(/gc) {
      # Begin a new sub-array
      my $CurAtom = [];
      # Add to current atom. If there's a stack, must be within a bracket
      if (scalar @AtomStack) {
        push @$AtomRef, $CurAtom;
      } else {
        $$AtomRef = $CurAtom;
      }

      # Check for simple response list to fast parse
      if ($Line =~ m/\G([^()\"{}~\s]+(?: [^()\"{}~\s]+)*)\) ?/gc) {
        push @$CurAtom, map { $_ eq 'NIL' ? undef : $_ } split(' ', $1);

      } else {
        # Add current ref to stack and update
        push @AtomStack, $AtomRef;
        $AtomRef = $CurAtom;
      }

    }

    # End bracket? (and possible trailing space)
    elsif ($Line =~ m/\G\) ?/gc) {
      # Close existing sub-array
      if (!scalar @AtomStack) {
        die "IMAPTalk: Unexpected close bracket in IMAP response : '$Line'";
      }
      $AtomRef = pop @AtomStack;
    }

    # Literal or binary literal? (Must end line)
    elsif ($Line =~ m/\G~?\{(\d+)\}$/gc) {
      my $Bytes = $1;
      $CurAtom = undef;
      if ($Self->{LiteralControl}) {
        if (ref($Self->{LiteralControl}) eq 'CODE') {
          $CurAtom = $Self->{LiteralControl}->($Bytes);
        } else {
          $CurAtom = $Self->{LiteralControl};
        }
      }
      if ($CurAtom) {
        $Self->_copy_imap_socket_to_handle($CurAtom, $Bytes);
      }
      else {
        # Capture with regexp to untaint
        my $Content = $Self->_imap_socket_read_bytes($Bytes);
        ($CurAtom) = ($Content =~ /^(.*)$/s);
      }
      # Read new line and strip first space if any
      $Line = $Self->_imap_socket_read_line();
      $Line =~ s/^ //;
      # Add to current atom. If there's a stack, must be within a bracket
      if (scalar @AtomStack) {
        push @$AtomRef, $CurAtom;
      } else {
        $$AtomRef = $CurAtom;
      }
    }

    # End of line?
    elsif ($Line =~ m/\G$/gc) {
      # Should not be within brackets
      if (scalar @AtomStack) {
        die "IMAPTalk: Unexpected end of line in IMAP response : '".$Self->{ReadLine}."'";
      }
      # Otherwise fine, we're about to exit anyway
    }

    else {
      die "IMAPTalk: Error parsing atom in IMAP response : '$Line'";
    }

  # Repeat while we're within brackets
  } while (scalar @AtomStack);

  # Return rest of line to read line buffer
  $Self->{ReadLine} = substr($Line, pos($Line) // 0);

  return $Atom;
}

=item I<_next_simple_atom($Self)>

Faster version of _next_atom() for known simple cases

=cut
sub _next_simple_atom {
  my $Self = shift;

  # Fill line buffer if nothing left
  my $Line = $Self->{ReadLine};
  $Line = $Self->_imap_socket_read_line() if !defined $Line;

  # Should be single item
  if ($Line =~ m/\G([^()\"{}~\s]+) ?/gc) {
    my $Atom = $1 eq 'NIL' ? undef : $1;

    # Return rest of line to read line buffer
    $Self->{ReadLine} = substr($Line, pos($Line));

    return $Atom;
  } else {
    die "IMAPTalk: Expected simple atom, got: " . substr($Line, 0, 100);
  }
}

=item I<_remaining_atoms($Self)>

Returns all the remaining atoms for the current line in the read line
buffer as an array reference. Leaves $Self->{ReadLine} eq ''.
See C<_next_atom()>

=cut
sub _remaining_atoms() {
  my ($Self, $SlurpIDs) = @_;

  # A hack. 'search' and 'sort' commands return a ID/UID list to end-of-line.
  #  Use a quick loop to pull these out one at a time and cast to int() which
  #  reduces memory usage, and is faster than general _next_atom() calls
  if ($SlurpIDs) {
    my $res = _read_int_list($Self->{ReadLine});
    $Self->{ReadLine} = '';
    return $res;
  }

  my @AtomList;

  # Pull all atoms until no line left
  while ($Self->{ReadLine} ne '') {
    push @AtomList, $Self->_next_atom();
  }

  return \@AtomList;
}

=item I<_remaining_line($Self)>

Returns the remaining data in the read line buffer ($Self->{ReadLine}) as
a scalar string/data value.

=cut
sub _remaining_line {
  my $Line = $_[0]->{ReadLine};
  $_[0]->{ReadLine} = '';
  return $Line;
}

=item I<_fill_imap_read_buffer($Self)>

Wait until data is available on the IMAP connection socket (or a timeout
occurs). Read the data into the internal buffer $Self->{ReadBuf}. You
can then use C<_imap_socket_read_line()>, C<_imap_socket_read_bytes()>
or C<_copy_imap_socket_to_handle()> to read data from the buffer in
lines or bytes at a time.

=cut
sub _fill_imap_read_buffer {
  my ($Self, $Timeout, $Append) = @_;
  my $Buffer = '';
  $Timeout = $Self->{Timeout} if !defined $Timeout;
  my $Blocking = $Self->{UseBlocking};

  # Timeout not 0, nothing to do if buffer already has data.
  if (!defined($Timeout) || $Timeout != 0) {
    return 1 if !$Append && length($Self->{ReadBuf});
  }

  # Wait for data to become available, signals can interrupt
  # select() calls, so loop until definitely past $Timeout time
  my @ReadList;
  my ($StartTime, $UsedTime) = (time, 0);
  do {
    if ($Blocking) {
      @ReadList = ( $Self->{Socket} );
    }
    else {
      my $ThisTimeout = $Timeout;
      @ReadList =
        $Self->{Select}->can_read(
        defined($ThisTimeout) ? ( $ThisTimeout - $UsedTime ) : () );
    }
    $UsedTime = time - $StartTime;
  } while (!@ReadList && (!defined($Timeout) || $UsedTime < $Timeout));

  # If no handles, then timedout
  if (scalar(@ReadList) == 0) {
    die "IMAPTalk: Read timed out on socket";
  }

  # Check assumption...
  if ($ReadList[0] != $Self->{Socket}) {
    die "IMAPTalk: Read handles don't match. Internal error";
  }

  # Now read data into read buffer
  my $IsBlocking = $Self->{Socket}->blocking();
  $Self->{Socket}->blocking(0) if !$Blocking;
  my $BytesRead = $Self->{Socket}->sysread($Buffer, 16384);
  $Self->{Socket}->blocking($IsBlocking) if !$Blocking;
  CORE::select(undef, undef, undef, 0.25) if $Self->{go_slow};

  # The select told us there was data, if there wasn't
  # any, it means the other end closed the connection
  if (!defined $BytesRead || $BytesRead == 0) {
    $Self->state(Unconnected);
    die "IMAPTalk: IMAP Connection closed by other end: $!";
  }

  # Store in read buffer
  $Self->{ReadBuf} .= $Buffer;

  return 1;
}

=item I<_imap_socket_read_line($Self)>

Read a \r\n terminated list from the buffered IMAP connection socket.

=cut
sub _imap_socket_read_line {
  my $Self = shift;

  while (1) {

    # Got end of line chars?
    if ((my $LineLen = index($Self->{ReadBuf}, LB)) != -1) {

      # Remove line from buffer (including CRLF)
      my $Line = substr($Self->{ReadBuf}, 0, $LineLen + LBLEN, '');
      $Self->_trace("S: " . substr($Line, 0, - LBLEN) . "\n") if $Self->{Trace};

      # Remove CRLF on return
      return substr($Line, 0, - LBLEN);
    }

    # Add to buffer
    $Self->_fill_imap_read_buffer(undef, 1);
  }
  return 1;
}

=item I<_imap_socket_read_bytes($Self, $NBytes)>

Read a certain number of bytes from the buffered IMAP connection socket.

=cut
sub _imap_socket_read_bytes {
  my ($Self, $Bytes) = @_;

  while (length($Self->{ReadBuf}) < $Bytes) {
    $Self->_fill_imap_read_buffer(undef, 1);
  }

  return substr($Self->{ReadBuf}, 0, $Bytes, '');
}

=item I<_imap_socket_out($Self, $Data)>

Write the data in $Data to the IMAP connection socket.

=cut
sub _imap_socket_out {
  my $Self = shift;

  # Do tracing
  $Self->_trace("C: " . $_[0]) if $Self->{Trace};

  # Keep track of bytes written and total number to write
  my ($WCount, $TCount) = (0, length($_[0]));

  # Loop to write out all the data if needs multiple passes
  while ($TCount != $WCount) {
    my $NWrite = $Self->{Socket}->syswrite($_[0], $TCount - $WCount, $WCount);
    if (!defined $NWrite) {
      # A bit hacky, but try and avoid exposing password
      my $Data = $_[0];
      $Data =~ s/^(\d+ login \S+ )("(?:\\.|[^"])*?"|[^"\s]*)/$1 . ("*" x length($2))/e;
      my $TryData = substr($Data, $WCount, $TCount - $WCount);
      die 'IMAPTalk: Error writing data "' . Dumper($TryData) . '" to socket.';
    }
    $WCount += $NWrite;
  }
  return 1;
}

=item I<_copy_handle_to_handle($Self, $InHandle $OutHandle, $NBytes)>

Copy a given number of bytes from one handle to another.

The number of bytes specified ($NBytes) must be available on the IMAP socket,
otherwise the function will 'die' with an error if it runs out of data.

If $NBytes is not specified (undef), the function will attempt to
seek to the end of the file to find the size of the file.
 
=cut
sub _copy_handle_to_handle {
  my ($Self, $InHandle, $OutHandle, $NBytes) = @_;

  # If NBytes undef, seek to end to find total length
  if (!defined $NBytes) {
    seek($InHandle, 0, 2); # SEEK_END
    $NBytes = tell($InHandle);
    seek($InHandle, 0, 0); # SEEK_SET
  }

  # Loop over in handle reading chunks at a time and writing to the out handle
  my $Val;
  while (my $NRead = $InHandle->read($Val, 8192)) {
    if (!defined $NRead) {
      die 'IMAPTalk: Error reading data from io handle.' . $!;
    }

    my $NWritten = 0;
    while ($NWritten != $NRead) {
      my $NWrite = $OutHandle->syswrite($Val, $NRead-$NWritten, $NWritten);
      if (!defined $NWrite) {
        die 'IMAPTalk: Error writing data to io handle.' . $!;
      }
      $NWritten += $NWrite;
    }
  }

  # Done
  return 1;
}

=item I<_copy_imap_socket_to_handle($Self, $OutHandle, $NBytes)>

Copies data from the IMAP socket to a file handle. This is different
to _copy_handle_to_handle() because we internally buffer the IMAP
socket so we can't just use it to copy from the socket handle, we
have to copy the contents of our buffer first.

The number of bytes specified must be available on the IMAP socket,
if the function runs out of data it will 'die' with an error.
 
=cut
sub _copy_imap_socket_to_handle {
  my ($Self, $OutHandle, $NBytes) = @_;

  # Loop over socket reading chunks at a time and writing to the out handle
  my $Val;
  while ($NBytes) {
    my $NToRead = ($NBytes > 16384 ? 16384 : $NBytes);
    $Val = $Self->_imap_socket_read_bytes($NToRead);
    my $NRead = length($Val);
    if (length($Val) == 0) {
      die 'IMAPTalk: Error reading data from socket.' . $@;
    }
    $NBytes -= $NRead;

    my $NWritten = 0;
    while ($NWritten != $NRead) {
      my $NWrite = syswrite($OutHandle,$Val, $NRead-$NWritten, $NWritten);
      if (!defined $NWrite) {
        die 'IMAPTalk: Error writing data to io handle.' . $@;
      }
      $NWritten += $NWrite;
    }
  }

  # Done
  return 1;
}
  
=item I<_quote($String)>

Returns an IMAP quoted version of a string. This place "..." around the
string, and replaces any internal " with \".
 
=cut
sub _quote {
  # Replace " and \ with \" and \\ and surround with "..."
  my $Str = shift;
  $Str =~ s/(["\\])/\\$1/g;
  return \qq{"$Str"};
}

=back
=cut

=head1 INTERNAL PARSING FUNCTIONS

=over 4
=cut

=item I<_parse_list_to_hash($ListRef, $Recursive)>

Parses an array reference list of ($Key, $Value) pairs into a hash.
Makes sure that all the keys are lower cased (lc) first.

=cut
sub _parse_list_to_hash {
  my $ContentHashList = shift || [];
  my $Recursive = shift;

  ref($ContentHashList) eq 'ARRAY' || return { };

  my %Res;
  while (@$ContentHashList) {
    my ($Param, $Val) = (shift @$ContentHashList, shift @$ContentHashList);

    $Val = _parse_list_to_hash($Val, $Recursive-1)
      if (ref($Val) && $Recursive);

    $Res{lc($Param)} = $Val;
  }

  return \%Res;
}

sub _find_arg {
  my ($Self, $Args, $Term, $CB) = @_;

  for (0 .. @$Args-1) {
    if (!ref $Args->[$_] && lc($Args->[$_]) eq $Term) {
      # Alias arg into $_ and call callback
      $CB->() for $Args->[$_+1];
    }
  }
}

=item I<_fix_folder_name($FolderName, $WildCard)>

Changes a folder name based on the current root folder prefix as set
with the C<set_root_prefix()> call.

If $WildCard is true, then a folder name with % or *
is left alone.

=cut
sub _fix_folder_name {
  my ($Self, $FolderName, $WildCard) = @_;

  return '' if $FolderName eq '';

  $FolderName = $Self->_fix_folder_encoding($FolderName);

  return $FolderName if $WildCard && $FolderName =~ /[\*\%]/;

  # XXX - make more general/configurable
  return $FolderName if $FolderName =~ m{^DELETED\.user\.};
  return $FolderName if $FolderName =~ m{^RESTORED\.};

  my $RootFolderMatch = $Self->{RootFolderMatch}
    || return $FolderName;

  # If no root folder, just return passed in folder
  return $FolderName if $FolderName =~ $RootFolderMatch;

  my ($RootFolder, $Separator) = @$Self{'RootFolder', 'Separator'};
  return !$RootFolder ? $FolderName : $RootFolder . $Separator . $FolderName;
}

=item I<_fix_folder_encoding($FolderName)>

Encode folder name using IMAP-UTF-7

=cut
sub _fix_folder_encoding {
  my ($Self, $FolderName) = @_;

  if ( $Self->unicode_folders()
    && ( $FolderName =~ m{[^\x00-\x25\x27-\x7f]} ) )
  {
    $FolderName = Encode::encode( 'IMAP-UTF-7', $FolderName );
  }

  return $FolderName;
}

=item I<_unfix_folder_name($FolderName)>

Unchanges a folder name based on the current root folder prefix as set
with the C<set_root_prefix()> call.

=cut
sub _unfix_folder_name {
  my ($Self, $FolderName) = @_;

  # Normalise root folder part
  my $RFN = $Self->{RootFolderNormalise};
  $FolderName =~ s/^$RFN/$Self->{RootFolder}$1/ if $RFN;

  my $UFM = $Self->{UnrootFolderMatch};
  $FolderName =~ s/^$UFM// if $UFM;

  my $UnicodeFolders = $Self->unicode_folders();
  if ( $UnicodeFolders && ( $FolderName =~ m{&} ) )
  {
    $FolderName = Encode::decode( 'IMAP-UTF-7', $FolderName );
  }

  return $FolderName;
}

=item I<_fix_message_ids($MessageIds)>

Used by IMAP commands to handle a number of different ways that message
IDs can be specified.

=item I<Method arguments>

=over 4

=item B<$MessageIds>

String or array ref which specified the message IDs or UIDs.

=back

The $MessageIds parameter may take the following forms:

=over 4

=item B<array ref>

Array is turned into a string of comma separated ID numbers.

=item B<1:*>

Normally a * would result in the message ID string being quoted.
This ensure that such a range string is not quoted because some
servers (e.g. cyrus) don't like.

=back

=cut
sub _fix_message_ids {
  my $Item = shift;
  # If the item is an array reference, turn into a comma separated of items
  if (ref($Item) eq 'ARRAY') {
    my @Src = sort { $a <=> $b } @$Item;
    push @Src, 0; # end marker to make the logic below simpler
    my @Dest;
    my $Start;
    my $Prev;
    while (defined (my $Single = shift @Src)) {
      if (defined $Prev and $Single == $Prev + 1) {
        $Start = $Prev unless defined $Start;
      }
      else {
        if (defined $Start) {
          push @Dest, "$Start:$Prev";
          $Start = undef;
        }
        elsif (defined $Prev) {
          push @Dest, $Prev;
        }
      }
      $Prev = $Single;
    }
    # Make scalar ref, so we don't quote
    $Item = \join(',', @Dest);
  }
  # If the item ends in a *, don't put "'s around it. This is
  # a hack so "1:*" doesn't end up with quotes that cyrus doesn't like
  $Item = \"$Item" if !ref($Item) && $Item =~ /\*$/;
  return $Item;
}

=item I<_parse_email_address($EmailAddressList)>

Converts a list of IMAP email address structures as parsed and returned
from an IMAP fetch (envelope) call into a single RFC 822 email string
(e.g. "Person 1 Name" <ename@ecorp.com>, "Person 2 Name" <...>, etc) to
finally return to the user.

This is used to parse an envelope structure returned from a fetch call.
  
See the documentation section 'FETCH RESULTS' for more information.

=cut
sub _parse_email_address {
  my $EmailAddressList = shift || [];
  my $DecodeUTF8 = shift;

  # Email addresses always come as a list of addresses (possibly in groups)
  my @EmailGroups = ([ undef ]);
  foreach my $Adr (@$EmailAddressList) {

    # Check address assumption
    scalar(@$Adr) == 4
      || die "IMAPTalk: Wrong number of fields in email address structure " . Dumper($Adr);

    # No hostname is start/end of group
    if (!defined $Adr->[0] && !defined $Adr->[3]) {
      push @EmailGroups, [ $Adr->[2] ];
      next;
    }

    # Build 'ename@ecorp.com' part

    # If domain is "unspecified-domain" and no name part, move localpart to name part
    if (defined $Adr->[3] && $Adr->[3] eq "unspecified-domain" && !$Adr->[0]) {
      @$Adr[0,2,3] = ($Adr->[2], undef, undef);
    }

    my $EmailAdr = defined $Adr->[2] ? $Adr->[2] : '';
    my $EmailDom = defined $Adr->[3] ? $Adr->[3] : '';
    my $EmailStr = $EmailAdr || $EmailDom ? $EmailAdr . '@' . $EmailDom : '';

    # If the email address has a name, add it at the start and put <> around address
    if (defined $Adr->[0] and $Adr->[0] ne '') {
      # CRLF's are folding that's leaked into data where it shouldn't, strip them
      $Adr->[0] =~ s/\r?\n//g;
      _decode_utf8($Adr->[0]) if $DecodeUTF8 && $Adr->[0] =~ $NeedDecodeUTF8Regexp;
      # Strip any existing " and \ chars
      $Adr->[0] =~ s/["\\]//g;
      $EmailStr = '"' . $Adr->[0] . '"' . ($EmailStr ? ' <' . $EmailStr . '>' : '');
    }

    push @{$EmailGroups[-1]}, $EmailStr;
  }

  # Join the results with commas between each address, and "groupname: adrs ;" for groups
  for (@EmailGroups) {
    my $GroupName = shift @$_;
    ($_ = undef), next if !defined $GroupName && !@$_;
    my $EmailAdrs = join ", ", @$_;
    $_ = defined($GroupName) ? $GroupName . ': ' . $EmailAdrs . ';' : $EmailAdrs;
  }

  return join " ", grep { defined $_ } @EmailGroups;
}

=item I<_parse_envelope($Envelope, $IncludeRaw, $DecodeUTF8)>

Converts an IMAP envelope structure as parsed and returned from an
IMAP fetch (envelope) call into a convenient hash structure.

If $IncludeRaw is true, includes the XXX-Raw fields, otherwise
these are left out.

If $DecodeUTF8 is true, then checks if the fields contain
any quoted-printable chars, and decodes them to a Perl UTF8
string if they do.

See the documentation section 'FETCH RESULTS' from more information.

=cut
sub _parse_envelope {
  my ($Env, $IncludeRaw, $DecodeUTF8) = @_;

  # Check envelope assumption
  scalar(@$Env) == 10
    || die "IMAPTalk: Wrong number of fields in envelope structure " . Dumper($Env);

  _decode_utf8($Env->[1]) if $DecodeUTF8 && defined($Env->[1]) && $Env->[1] =~ $NeedDecodeUTF8Regexp;

  # Setup hash directly from envelope structure
  my %Res = (
    'Date',        $Env->[0],
    'Subject',     $Env->[1],
    'From',        _parse_email_address($Env->[2], $DecodeUTF8),
    'Sender',      _parse_email_address($Env->[3], $DecodeUTF8),
    'Reply-To',    _parse_email_address($Env->[4], $DecodeUTF8),
    'To',          _parse_email_address($Env->[5], $DecodeUTF8),
    'Cc',          _parse_email_address($Env->[6], $DecodeUTF8),
    'Bcc',         _parse_email_address($Env->[7], $DecodeUTF8),
    ($IncludeRaw ? (
      'From-Raw',    $Env->[2],
      'Sender-Raw',  $Env->[3],
      'Reply-To-Raw',$Env->[4],
      'To-Raw',      $Env->[5],
      'Cc-Raw',      $Env->[6],
      'Bcc-Raw',     $Env->[7],
    ) : ()),
    'In-Reply-To', $Env->[8],
    'Message-ID',  $Env->[9]
  );

  return \%Res;
}

=item I<_parse_bodystructure($BodyStructure, $IncludeRaw, $DecodeUTF8, $PartNum)>

Parses a standard IMAP body structure and turns it into a Perl friendly
nested hash structure. This routine is recursive and you should not
pass a value for $PartNum when called for the top level bodystructure
item.  Note that this routine destroys the array reference structure
passed in as $BodyStructure.

See the documentation section 'FETCH RESULTS' from more information

=cut
sub _parse_bodystructure {
  my ($Bs, $IncludeRaw, $DecodeUTF8, $PartNum, $IsMultipart) = @_;
  my %Res;

  # If the first item is a reference, then it's a MIME multipart structure
  if (ref($Bs->[0])) {

    # Multipart items are of the form: [ part 1 ] [ part 2 ] ...
    #  "MIME-Subtype" "Content-Type" "Content-Disposition" "Content-Language"

    # Process each mime sub-part recursively
    my ($Part, @SubParts);
    for ($Part = 1; ref($Bs->[0]); $Part++) {
      my $SubPartNum = ($PartNum ? $PartNum . "." : "") . $Part;
      my $Res = _parse_bodystructure(shift(@$Bs), $IncludeRaw, $DecodeUTF8, $SubPartNum, 1);
      push @SubParts, $Res;
    }

    # Setup multi-part hash
    %Res = (
      'MIME-Subparts',       \@SubParts,
      'MIME-Type',           'multipart',
      'MIME-Subtype',        lc(shift(@$Bs) // ''),
      'Content-Type',        _parse_list_to_hash(shift(@$Bs)),
      'Disposition-Type',    lc(shift(@{$Bs->[0]}) // ''),
      'Content-Disposition', _parse_list_to_hash(@{shift(@$Bs)}),
      'Content-Language',    shift(@$Bs),
      'Content-Location',    shift(@$Bs),
      # Shouldn't be anything after this. Add as remainder if there is
      'Remainder',           $Bs
    );
  }

  # Otherwise it's a normal MIME entity
  else {

    # Get the mime type and sub-type
    my ($MimeType, $MimeSubtype) = (lc(shift(@$Bs)), lc(shift(@$Bs)));

    # Partnum for getting the text part of an entity. Do this
    #  here so recursive call works for any embedded messages
    $PartNum = $PartNum ? $PartNum . '.1' : '1'
      if !$IsMultipart;

    # Pull out special fields for 'text' or 'message/rfc822' types
    if ($MimeType eq 'text') {
      %Res = (
        'Lines',   splice(@$Bs, 5, 1)
      );
    } elsif ($MimeType eq 'message' && $MimeSubtype eq 'rfc822') {

      # message/rfc822 includes the messages envelope and bodystructure
      my @MsgParts = splice(@$Bs, 5, 3);
      %Res = (
        'Message-Envelope',       _parse_envelope(shift(@MsgParts), $IncludeRaw, $DecodeUTF8),
        'Message-Bodystructure',  _parse_bodystructure(shift(@MsgParts), $IncludeRaw, $DecodeUTF8, $PartNum),
        'Message-Lines',          shift(@MsgParts)
      );
    }

    # All normal mime-entities have these parts
    %Res = (
      %Res,
      'MIME-Type',                  $MimeType,
      'MIME-Subtype',               $MimeSubtype,
      'Content-Type',               _parse_list_to_hash(shift(@$Bs)),
      'Content-ID',                 shift(@$Bs),
      'Content-Description',        shift(@$Bs),
      'Content-Transfer-Encoding',  shift(@$Bs),
      'Size',                       shift(@$Bs),
      'Content-MD5',                shift(@$Bs),
      'Disposition-Type',           lc(shift(@{$Bs->[0]}) // ''),
      'Content-Disposition',        _parse_list_to_hash(@{shift(@$Bs)}),
      'Content-Language',           shift(@$Bs),
      'Content-Location',           shift(@$Bs),
      # Shouldn't be anything after this. Add as remainder if there is
      'Remainder',                  $Bs
    );

  }

  # Finally set the IMAP body part number and overall mime type
  $Res{'IMAP-Partnum'} = $PartNum || '';
  $Res{'MIME-TxtType'} = $Res{'MIME-Type'} . '/' . $Res{'MIME-Subtype'};

  return \%Res;
}

=item I<_parse_fetch_annotation($AnnotateItem)>

Takes the result from a single IMAP annotation item
into a Perl friendly structure. 

See the documentation section 'FETCH RESULTS' from more information.

=cut
sub _parse_fetch_annotation {
  my ($Value) = @_;

  return $Value unless ref($Value) eq 'ARRAY';
  my %Result = @$Value;
  map { $_ = { @$_ } if ref($_) eq 'ARRAY' } values %Result;

  return \%Result;
}

=item I<_parse_fetch_result($FetchResult)>

Takes the result from a single IMAP fetch response line and parses it
into a Perl friendly structure. 

See the documentation section 'FETCH RESULTS' from more information.

=cut
sub _parse_fetch_result {
  my ($FetchResult, $ParseMode) = @_;

  # Loop over fetch results
  my %ResultHash;
  while (@$FetchResult) {
    # Fetch results are in type, value pairs
    my $Type = lc(shift(@$FetchResult));
    my $Value = shift(@$FetchResult);

    # Process known fetch results into perl form
    if ($Type eq 'envelope') {
      $Value = _parse_envelope($Value, @$ParseMode{qw(EnvelopeRaw DecodeUTF8)})
        if $ParseMode->{Envelope};
    } elsif ($Type eq 'bodystructure') {
      $Value = _parse_bodystructure($Value, @$ParseMode{qw(EnvelopeRaw DecodeUTF8)})
        if $ParseMode->{BodyStructure};
    } elsif ($Type =~ /^(body|binary)(?:\.peek)?\[([^\]]*)/) {
      my $BodyArgs = $2;

      # Make 'body[]', 'body[]<0>', etc into plain 'body' (unless FullBody mode)
      $Type = $1;

      if ($BodyArgs =~ /^[\d.]*header/) {
        _parse_header_result($ResultHash{headers} ||= {}, $Value, $FetchResult);
      } else {
        $Type .= "[${BodyArgs}]" if $ParseMode->{FullBody}
      }
    } elsif ($Type eq 'annotation') {
      $Value = _parse_fetch_annotation($Value)
        if $ParseMode->{Annotation};
    }

    # Store result (either modified or original) into hash
    $ResultHash{$Type} = $Value;
  }

  return \%ResultHash;
}

=item I<_parse_header_result($HeaderResults, $Value, $FetchResult)>

Take a body[header.fields (xyz)] fetch response and parse out the
header fields and values

=cut
sub _parse_header_result {
  my ($HeaderResults, $Value, $FetchResult) = @_;

  # This is the response for requested headers
  # We don't care HOW they are requested, we just return what we've got
  # from the server, the result is returned in the key "headers"
  $Value = (splice(@$FetchResult,0,2))[1] if (ref($Value) eq 'ARRAY');

  my @HeaderLines = split(/[\r\n]+/,$Value);

  my $PrevHeader;
  for (@HeaderLines) {
    if (/^[\t ]+/){
      next unless $PrevHeader;
      # A continuation line belongs to the last element of the array
      $HeaderResults->{$PrevHeader}[-1] .= "\r\n" . $_;
      next;
    }
    next unless /^([\x21-\x39\x3b-\x7e]+):\s*(.*)$/;
    $PrevHeader = lc($1);
    push @{$HeaderResults->{$PrevHeader}}, $2;
  }
}

=item I<_decode_utf8($Value)>

Decodes the passed quoted printable value to a Perl UTF8 string.

=cut
sub _decode_utf8 {
  # Fix dumb, dumb ANSI_X3.4-1968 encoding. It's not actually a valid
  #  charset according to RFC2047, "." is an especial, so Encode ignores it
  # See http://en.wikipedia.org/wiki/ASCII for other aliases
  $_[0] =~ s/=\?ANSI_X3\.4-(?:1968|1986)\?/=?US-ASCII?/gi;
  eval { $_[0] = decode('MIME-Header', $_[0]); };
}

sub _read_int_list {
  my $line = shift;

  # substr and index is faster than regular expressions - we just trust
  # that the intervening characters are digits!
  my @List;
  my $oldpos = 0;
  while ((my $pos = index($line, ' ', $oldpos+1)) >= 0) {
    push @List, int(substr($line, $oldpos, ($pos - $oldpos)));
    $oldpos = $pos;
  }
  my $final = substr($line, $oldpos);
  push @List, int($final) if $final ne '' && $final ne ' ';

  return \@List;
}

=item I<_expand_sequence(@Sequences)>

Expand a list of IMAP id sequences into a full list of ids

=cut
sub _expand_sequence {
  my @Ids;
  for (@_) {
    push(@Ids, int($1) .. int($2)), redo if /\G(\d+):(\d+),?/gc;
    push(@Ids, int($1)), redo if /\G(\d+),?/gc;
    next if /\G$/;
    die "unexpected sequence: " . substr($_, pos($_));
  }
  return @Ids;
}

=back
=cut

=head1 PERL METHODS

=over 4
=cut

=item I<DESTROY()>

Called by Perl when this object is destroyed. Logs out of the
IMAP server if still connected.

=cut
sub DESTROY {
  my $e = $@;  # Save errors from code calling us
  eval {

  my $Self = shift;

  # If socket exists, and connection is open and authenticated or
  #   selected, do a logout
  if ($Self->{Socket} && 
        ($Self->state() == Authenticated || $Self->state() == Selected) &&
        $Self->is_open()) {
    $Self->logout();
    $Self->{Socket}->close();
  }

  };
  # $e .= "        (in cleanup) $@" if $@;
  $@ = $e;
}

=back
=cut

=head1 SEE ALSO

I<Net::IMAP>, I<Mail::IMAPClient>, I<IMAP::Admin>, RFC 3501

Latest news/details can also be found at:

http://cpan.robm.fastmail.fm/mailimaptalk/

Available on github at:

L<https://github.com/robmueller/mail-imaptalk/>

=cut

=head1 AUTHOR

Rob Mueller E<lt>cpan@robm.fastmail.fmE<gt>. Thanks to Jeremy Howard
E<lt>j+daemonize@howard.fmE<gt> for socket code, support and
documentation setup.

=cut

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2003-2013 by FastMail Pty Ltd

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;

