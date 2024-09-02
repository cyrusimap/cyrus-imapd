package Net::XmtpServer;

=head1 NAME

Net::XmtpServer - Implement SMTP/LMTP server skeleton

=head1 SYNOPSIS

  package MyServer;

  use Net::XmtpServer;
  use Net::Server::PreForkSimple;
  use base qw(Net::XmtpServer Net::Server::PreForkSimple);

  MyServer->run(
    max_servers => 5,
    ...
  );

  # Callbacks for each server event
  sub helo { }
  sub rcpt { }


=head1 DESCRIPTION

This module implements a SMTP/LMTP server skeleton. Basically
you derive from it, as well as a Net::Server::* personality,
and it handles all process_request() calls, interpreting the
SMTP/LTMP stream, and making callbacks as appropriate for
your code to deal with

=head1 ADDITIONAL OPTIONS

When executing the run() method of the Net::Server object,
you can pass extra options

=over 4

=item xmtp_personality

Either 'lmtp', 'smtp' or 'both'. Determines whether helo/ehlo or lhlo
works

=item store_msg

If true, all messages in the DATA part of a transaction
are stored into a file which can be used when the DATA
section is complete

=item xmtp_tmp_dir

Directory for holding temporary message spool files.
Default to /tmp

=item handle_mime

If true, tries to handle MIME structure of message as
passed and does extra callbacks

=item xmtp_timeout

Timeout value for handling entire transactions
Default 120 seconds

=item cmd_timeout

Timeout value for each command (not including data)
Default 30 seconds

=item data_timeout

Timeout value for DATA command
Default 60 seconds

=item max_messages

Maximum number of messages to process before existing a child

=back

=cut

# Use modules/constants {{{
use IO::File;
use File::Temp qw(tempfile);

# Avoid UTF-8 regexp issues. Treat everything as pure
#  binary data
no utf8;
use bytes;

# Standard use items
use Data::Dumper;
use strict;
use warnings;
# }}}

=head1 METHODS

=over 4
=cut

=item I<xmtplog($Self, $Level, $Msg)>

Pass to $Self->log($Level, "%s", $Msg)

=cut
sub xmtplog {
  # $_[0]->log($_[1], '%s', $_[2]);
  $_[0]->log($_[1] * 2, $_[2]);
}

=item I<post_configure_hook($Self)>

Catch configure options

=cut
sub post_configure_hook {
  my ($Self, $Xmtp, $Srv) = ($_[0], $_[0]->{xmtp} ||= {}, $_[0]->{server});

  # In old versions of Net::Server, parameters passed to "run" could
  # be accessed with $Self->{server}->{configure_args}.
  # In new versions they are available directly in $Self->{server}
  my $Config = $Srv->{configure_args};
  my %Options = $Config ? @{$Config} : %{$Srv};

  # Get config options
  @$Xmtp{qw(StoreMsg HandleMime Personality)}
    = @Options{qw(store_msg handle_mime xmtp_personality)};

  # Set timeout for each transaction
  $Xmtp->{XmtpTimeout} = $Options{xmtp_timeout} || 300;
  $Xmtp->{CmdTimeout} = $Options{cmd_timeout} || 30;
  $Xmtp->{DataTimeout} = $Options{data_timeout} || 60;

  $Xmtp->{MaxMessages} = $Options{max_messages} || 0;

  $Xmtp->{TmpDir} = $Options{xmtp_tmp_dir} || '/tmp';

  # Set personality regexp match
  my $Personality = $Xmtp->{Personality};
  my $PersonalityRE = qr/helo|ehlo/i;
  if ($Personality) {
    $PersonalityRE = qr/lhlo/i if $Personality eq 'lmtp';
    $PersonalityRE = qr/helo|ehlo|lhlo/i if $Personality eq 'both';
  }
  $Xmtp->{PersonalityRE} = $PersonalityRE;

}

=item I<pre_loop_hook($Self)>

Called after ownership chage. Create dir to hold spool files.

=cut
sub pre_loop_hook {
  my ($Self, $Xmtp, $Srv) = ($_[0], $_[0]->{xmtp}, $_[0]->{server});

  # Get temporary dir, and clean
  if ($Xmtp->{StoreMsg}) {
    my $TmpDir = $Xmtp->{TmpDir};
    -d $TmpDir || mkdir $TmpDir;
    unlink glob("$TmpDir/*.xmtp");
  }

}

=item I<child_init_hook($Self)>

Called when a new child is forked. Create temp spool file

=cut
sub child_init_hook {
  my ($Self, $Xmtp, $Srv) = ($_[0], $_[0]->{xmtp}, $_[0]->{server});

  # Return if already inited. Possible because post_accept_hook()
  #  calls us. This is so non-forking debug versions work as well
  return 1 if $Xmtp->{ChildInit};

  srand($$ + time());

  # Don't inherit parent child signal handling
  #  Otherwise system("...") or `cmd` calls fail...
  $SIG{CHLD} = 'IGNORE';
  $SIG{PIPE} = 'IGNORE';

  # Create temporary spool file for this child
  if ($Xmtp->{StoreMsg}) {
    my $TmpDir = $Xmtp->{TmpDir};
    my ($Fh, $Filename) = tempfile(DIR => $TmpDir, UNLINK => 1, SUFFIX => '.xmtp');
    bless $Fh, "IO::File";

    # Same in server properties
    @$Xmtp{qw(Fh Filename)} = ($Fh, $Filename);
  }

  $Xmtp->{ChildInit} = 1;
  return 0;
}

=item I<post_accept_hook($Self)>

Check for init requirements.

If running in debug non-forking mode, then child_init_hook()
won't be called, so we try calling it now

=cut
sub post_accept_hook {
  $_[0]->child_init_hook();
}

=item I<process_request($Self)>

Process a new accepted connection from a client

=cut
sub process_request {
  my ($Self, $Xmtp, $Srv) = ($_[0], $_[0]->{xmtp}, $_[0]->{server});

  eval {

  $Self->start_request();

  $Self->ClearAlarm();

  # Reset any existing state
  $Self->reset_state();

  # Notify of new client connection
  $Self->new_connection();
  $Self->xmtplog(2, "New connection");

  # Setup timeout handler (after new_connection, which might
  #  change $SIG{ALRM} itself)
  $SIG{ALRM} = sub {
    my ($Package, $Filename, $Line, $Sub) = caller(0);
    my $LastCmd = $Xmtp->{LastCmd} || '';
    die "Timeout: State=$LastCmd; In=${Sub}; Line=$Line";
  };

  # Do all the connection work
  $Self->HandleConnection();

  alarm(0);
  };

  if (my $Err = $@) {
    if ($Err =~ /^Timeout/) {
      $Self->timeout($Err);
    } else {
      $Self->error($Err);
      $Self->xmtplog(1, "Processing error: $Err");
    }
  }

  # Stop timeout alarm
  alarm(0);

  $Self->close_connection();

  $Self->end_request();
}

sub HandleConnection {
  my $Self = shift;

  # Simple three states
  #  0 = done/quit
  #  1 = command mode
  #  2 = data mode
  my $Mode = 1;
  while ($Mode) {
    if ($Mode == 1) {
      $Mode = $Self->HandleModeCommand();
    } elsif ($Mode == 2) {
      $Mode = $Self->HandleModeData();
    } else {
      die "Unknown mode: $Mode";
    }
  }
}

sub HandleModeCommand {
  my ($Self, $Xmtp, $Srv) = ($_[0], $_[0]->{xmtp}, $_[0]->{server});

  # Schedule command timeout
  $Self->ScheduleAlarm($Xmtp->{CmdTimeout});

  # Loop over commands and dispatch each
  while (defined($_ = <STDIN>)) {
    # Remove EOL chars for processing below
    s/[\r\n]*$//;

    $Xmtp->{LastCmd} = $_;
    $Self->xmtplog(2, "Received command: $_");

    if (my ($To, $ToExtra) = /^RCPT\s+TO:\s*(.*?)\s*$/i) {
      ($To, $ToExtra) = ($To =~ /^<?([^>@]*\@?[^>\s]*)>?\s*(.*?)$/);
      $Self->rcpt_to($To || '', split /\s+/, ($ToExtra || ''));

    } elsif (my ($From, $FromExtra) = /^MAIL\s+FROM:\s*(.*?)\s*$/i) {
      $From =~ s/^<([^>]*)>\s*|^([^<]\S*)\s*//;
      ($From, $FromExtra) = (defined($1) ? $1 : $2, $From);
      $Self->mail_from($From || '', split /\s+/, ($FromExtra || ''));

    } elsif (my ($Helo) = /^$Xmtp->{PersonalityRE}\s+(.*?)\s*$/i) {
      $Self->helo($Helo);

    } elsif (my ($RsetExtra) = /^RSET\s*(.*?)\s*$/i) {
      # If rset returns true, means we're done with this connection.
      #  Switch to mode 0, which exits connection
      my $Done = $Self->rset(split /\s+/, ($RsetExtra || ''));
      $Self->reset_state();
      return 0 if $Done;

    } elsif (/^DATA\s*$/i) {
      # Note start of data section
      #  Returns false if failure...
      next if !$Self->begin_data();

      # Switch to data mode
      return 2;

    } elsif (/^QUIT\s*$/i) {
      $Self->quit();
      return 0;

    } elsif (/^NOOP\s*$/i) {
      $Self->noop();

    } else {
      $Self->unknown($_);
    }

    # Reschedule alarm if still in cmd mode
    $Self->ScheduleAlarm($Xmtp->{CmdTimeout});
  }

  # EOF on input, done/exit mode
  return 0;
}

sub HandleModeData {
  my ($Self, $Xmtp, $Srv) = ($_[0], $_[0]->{xmtp}, $_[0]->{server});

  # Schedule correct alarm
  $Self->ScheduleAlarm($Xmtp->{DataTimeout});

  # MIME body buffering details
  my ($HeadBuffer, $DoBodyBuffer, $BodyBuffer) = ('', 0, '');

  $Self->begin_headers();

  # MIME message boundary regexps
  my ($InHeader, $MessageHdrs, @Boundaries, $UUEnc, $BinHex) = (1, 1);

  # Processing options
  my ($Fh, $HandleMime) = @$Xmtp{qw(Fh HandleMime)};

  # Main processing loop
  while (defined($_ = <STDIN>)) {
    # Remove all null chars
    tr/\000//d;
    # Normalise to \n line endings
    s/\r+\n$/\n/;

    # Lone . is always EOD
    if ($_ eq ".\n") {

      if ($Xmtp->{HandleMime}) {
        if ($InHeader) {
          $Self->ProcessHeaders(\$HeadBuffer, \@Boundaries, $MessageHdrs);
          $Self->end_headers(\$HeadBuffer);
          $Self->output_headers($Fh, $HeadBuffer) if $Fh;
        } else {
          $Self->end_body(\$BodyBuffer);
          $Self->output_body($Fh, $BodyBuffer) if $Fh && $DoBodyBuffer;
        }
      }

      return $Self->HandleEndOfData() ? 0 : 1;

    # Otherwise handle header/mime/data line
    } else {

      # Un-dot-stuff
      s/^\.//;

      # If not handling MIME, just add straight to spool file
      if (!$HandleMime) {
        $Self->output_body($Fh, $_) if $Fh;

      # Handle MIME phases ... {{{
      } else {

        if ($InHeader) {
          # Strip bare \r's from headers
          s/\r//g;

          $HeadBuffer .= $_;

          # End of headers
          if ($_ eq "\n") {
            $MessageHdrs = $Self->ProcessHeaders(\$HeadBuffer, \@Boundaries, $MessageHdrs);
            $Self->end_headers(\$HeadBuffer);

            $Self->output_headers($Fh, $HeadBuffer) if $Fh;
            $HeadBuffer = '';

            # If message/rfc822 attachment, then we're immediately into headers again
            if (!$MessageHdrs) {
              $InHeader = 0;
              $DoBodyBuffer = $Self->begin_body();
            }
          }

        # In 'body' type section
        } else {

          # Found boundary string?
          if (@Boundaries && /$Boundaries[-1]->[1]/) {
            $Self->end_body(\$BodyBuffer);
            $Self->output_body($Fh, $BodyBuffer) if $Fh && $DoBodyBuffer;
            $BodyBuffer = '';
            $DoBodyBuffer = 0;

            # Use previous boundary match
            pop @Boundaries if /--\s*$/;

            if (@Boundaries) {
              $InHeader = 1;
              $Self->begin_headers();
            }
          }

          # Always send body to spool file/buffer
          if ($DoBodyBuffer) {
            $BodyBuffer .= $_;
          } else {
            $Self->output_body($Fh, $_) if $Fh;
          }

          # UUENCODE begin type section
          if (/^begin(?:-base64)? \d{1,4}/) {
            $Self->uuenc_begin($_);
            $UUEnc = 1;
          } elsif ($UUEnc && /^(?:end|====)/) {
            $Self->uuenc_end($_);
            $UUEnc = 0;
          }

          # BINHEX type section
          if (/^\(This file must be converted with BinHex 4\.0\)/) {
            $Self->binhex_begin($_);
            $BinHex = 1;
          } elsif ($BinHex && /:$/) {
            $Self->binhex_end($_);
            $BinHex = 0;
          }

        }
      }

      # }}}

    }

  # Main while loop
  }

  # EOF on input, done/exit mode
  return 0
}

sub ProcessHeaders {
  my ($Self, $HeadBuffer, $Boundaries, $MsgHeaders) = @_;

  # Loop through and list all headers (minus \n)
  my @Headers;
  while ($$HeadBuffer =~ /\G([^\s:]+)(:[ \t]*(?:\n[ \t]+)*)([^\n]*(?:\n[ \t]+[^\n]*)*)\n/gc) {
    push @Headers, [ $1, $2, $3 ]
  }
  my ($Remainder) = $$HeadBuffer =~ /\G(.*)$/s;

  # Build map (prefer earlier headers). Save refs
  my %Headers = map { lc($_->[0]) => $_ } reverse @Headers;
  @$Self{qw(HeaderList HeaderMap)} = (\@Headers, \%Headers);

  # Callback for each header (use counter because add_header() might be called)
  for (my $i = 0; $i < @Headers; $i++) {
    $Self->HandleHeader(@{$Headers[$i]}, $Boundaries, $MsgHeaders);
  }

  # Callback with all headers
  $Self->all_headers(\%Headers, \@Headers, $Boundaries, $MsgHeaders);

  # Don't need these refs any more
  delete @$Self{qw(HeaderList HeaderMap)};

  # Build headers again
  $$HeadBuffer = join "", map { !defined $_->[2] ? "" : join("", @$_, "\n") } @Headers;
  $$HeadBuffer .= $Remainder;

  # Extract new MIME boundary details in content-type headers
  if (my $ContentType = $Headers{'content-type'}) {
    $Self->HandleContentTypeHeader($Boundaries, $ContentType->[2]);

    # Return true if message/rfc822 attachment
    if ($ContentType->[2] =~ m{^message/rfc822}i) {
      # We're inside a message now
      $Boundaries->[-1]->[2]++ if @$Boundaries;
      return 1;
    }
  }

  return 0;
}

sub HandleHeader {
  my ($Self, $HeaderName, $HeaderSep, $HeaderValue, $Boundaries, $MsgHeaders) = @_;

  # Process existing header
  if ($HeaderName) {

    # Callback to inspect (and possibly modify) header "name: value" pair
    my $OldValue = $HeaderValue;
    $Self->header($HeaderName, $HeaderValue, scalar(@$Boundaries), $MsgHeaders);

    # If old header was empty value, add space into separator if not present
    $HeaderSep .= " " if !$OldValue && $HeaderValue && $HeaderSep eq ':';

    # Save any changes back
    ($_[1], $_[2], $_[3]) = ($HeaderName, $HeaderSep, $HeaderValue);
  }

  return;
}

sub HandleContentTypeHeader {
  my ($Self, $Boundaries, $HeaderValue) = @_;

  # Put current mime type string into boundary details
  my ($MimeType) = $HeaderValue =~ /^([^;\s]+)/;
  $Boundaries->[-1]->[4] = $MimeType if @$Boundaries;

  # Get boundary string
  my ($Boundary) = $HeaderValue =~ /boundary="([^"]+)"/i;
  ($Boundary) = $HeaderValue =~ /boundary=([^\s;]+)/i if !$Boundary;
  return if !$Boundary;

  my $BoundaryRE = qr/^--\Q$Boundary\E(?:--)?\s*$/;

  # Track how deep we are in attached messages
  my $MessageDepth = @$Boundaries ? $Boundaries->[-1]->[2] : 0;

  # Create match regexp
  push @$Boundaries, [ $Boundary, $BoundaryRE, $MessageDepth, $MimeType, '' ];
}

sub HandleEndOfData {
  my ($Self, $Xmtp) = ($_[0], $_[0]->{xmtp});

  $Self->ClearAlarm();

  $Xmtp->{LastCmd} = "EOD .";

  # Flush data to file, call end of data callback and reset state
  $Xmtp->{Fh}->flush() if $Xmtp->{Fh};
  my $Done = $Self->end_data();
  $Self->reset_state();

  return $Done;
}

sub ClearAlarm {
  my ($Self, $Xmtp) = ($_[0], $_[0]->{xmtp}); shift;
  alarm(0);
  $Xmtp->{TotalTime} = $Xmtp->{XmtpTimeout};
  $Xmtp->{PrevTimeout} = undef;
}

sub ScheduleAlarm {
  my ($Self, $Xmtp) = ($_[0], $_[0]->{xmtp}); shift;
  my $Timeout = shift;

  # Total time left for transaction
  my $TotalTime = $Xmtp->{TotalTime};

  # Find if there was a previous alarm() set
  my $PrevTimeout = $Xmtp->{PrevTimeout};

  # Find remaining time on alarm
  my $RemTime = alarm(0);

  # A previous timeout value supplied to alarm()
  if ($PrevTimeout) {
    my $Used = $PrevTimeout - $RemTime;
    $TotalTime -= $Used;
    $TotalTime = 1 if $TotalTime < 1;

  # No previous timeout value, but there is now
  } else {
    $Xmtp->{PrevTimeout} = $Timeout;
  }

  $Xmtp->{TotalTime} = $TotalTime;

  # Set new alarm. Use less that timeout if
  #  global time left is < timeout specified
  my $NewAlarm = $TotalTime < $Timeout ? $TotalTime : $Timeout;
  alarm($NewAlarm);
}

sub GetSpoolFile {
  my ($Self, $Xmtp) = ($_[0], $_[0]->{xmtp});
  return @$Xmtp{qw(Fh Filename)};
}

sub add_header {
  my ($Self, $Header, $Value) = @_;

  my $Data = [ $Header, ": ", $Value ];
  push @{$Self->{HeaderList}}, $Data;
  $Self->{HeaderMap}->{lc $Header} = $Data;
}

# Callback prototypes {{{

sub reset_state {
  my ($Self, $Xmtp) = ($_[0], $_[0]->{xmtp});

  # Reset spool file
  if (my $Fh = $Xmtp->{Fh}) {
    $Fh->seek(0, 0);
    $Fh->truncate(0);
  }

  $Xmtp->{LastCmd} = "EOD Done";
}

sub start_request   { undef; }
sub end_request     { undef; }

sub new_connection  { undef; }
sub helo            { undef; }
sub noop            { $_[0]->send_client_resp(250, "250 2.0.0 ok"); }
sub mail_from       { undef; }
sub rcpt_to         { undef; }
sub rset            { undef; }
sub unknown         { undef; }
sub quit            { undef; }
sub close_connection { undef; }

sub begin_data      { undef; }
sub end_data        { undef; }
sub header          { undef; }
sub data_line       { undef; }

sub begin_headers   { undef; }
sub end_headers     { undef; }
sub all_headers     { undef; }
sub begin_body      { undef; }
sub end_body        { undef; }

sub uuenc_begin     { undef; }
sub uuenc_end       { undef; }
sub binhex_begin    { undef; }
sub binhex_end      { undef; }

sub output_headers  { print {$_[1]} $_[2]; }
sub output_body     { print {$_[1]} $_[2]; }

sub timeout         { undef; }
sub error           { undef; }
# }}}

=item I<send_client_resp($Self, $Code, $Msg)>

Send back to the connected client the given code and message

=cut
sub send_client_resp {
  my ($Self, $Code, @MsgLines) = @_;
  while (@MsgLines > 1) {
    my $Msg = shift @MsgLines;
    print STDOUT "$Code-$Msg\r\n";
  }
  my $Msg = shift @MsgLines;
  print STDOUT "$Code $Msg\r\n";
}

=back
=cut

=head1 AUTHOR

Rob Mueller E<lt>cpan@robm.fastmail.fmE<gt>

=cut

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2003-2017 by FastMail Pty Ltd

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
