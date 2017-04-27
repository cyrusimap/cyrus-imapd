For those upgrading from 2.3.X; newer releases of Cyrus IMAP will use
significantly more memory per selected mailbox.  This is not an error
or bug; it's a feature.  The newer code is holding more data and
metadata in memory for purposes of faster access to more of the
mailbox.  This is not a memory leak.
