use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'SIEVE::Cyrus',
    'VERSION_FROM' => 'Cyrus.pm', # finds $VERSION
    'LIBS'	=> ['-L../../acap/ -lacapsieve -lacap -lsasl -L../../lib/ -lcyrus -lssl -lcrypto'],   # e.g., '-lm' 
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> '-I../acap/',     # e.g., '-I/usr/include/other' 
);
