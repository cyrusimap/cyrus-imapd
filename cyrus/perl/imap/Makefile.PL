use ExtUtils::MakeMaker;

$DESTDIR = $ENV{DESTDIR};

# we now bless things with DESTDIR
sub translate {
    my $path = @_;
    return ($DESTDIR . $path);
}

$args = $ENV{PERL_MM_OPT};
$args .= " INSTALLSITELIB=" . translate($Config{installsitelib});
$args .= " INSTALLSITEARCH=" . translate($Config{installsitearch});
$args .= " INSTALLBIN=" . translate($Config{installbin});
$args .= " INSTALLSCRIPT=" . translate($Config{installscript});
$args .= " INSTALLMAN1DIR=" . translate($Config{installman1dir});
$args .= " INSTALLMAN3DIR=" . translate($Config{installman3dir});
$ENV{PERL_MM_OPT} = $args;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile( 
    'NAME'	=> 'Cyrus::IMAP',
    'ABSTRACT'  => 'Cyrus administrative interface',
    'VERSION_FROM' => 'IMAP.pm', # finds $VERSION
    'macro'	=> {'IMCLIENT_LIBS' => ''},	# hack
    'clean'	=> {'FILES' => 'libcyrperl.a cyradm'},
    'LIBS'	=> ['-lsasl -L../../../lib/ -lcyrus -lssl -lcrypto'],
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> '-I../../lib',     # e.g., '-I/usr/include/other' 
    'EXE_FILES' => [cyradm],
);
