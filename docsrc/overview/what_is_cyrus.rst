About Cyrus
===========

What is Cyrus
-------------

Electronic mail is a major infrastructure service of most organizations. At Carnegie Mellon the use of electronic mail has overshadowed the use of all other distributed services since the early 1990s. At that time, the Andrew Mail and Bulletin Board System (AMS) was a universally available service, and departments without AMS ran their own mail systems. AMS has since been deprecated, and Project Cyrus is now the campus-wide mail system.

Cyrus is a highly scalable enterprise mail system designed for use in enterprise environments of various sizes using standards based technologies. Cyrus technologies scale from independent use in email departments to a system centrally managed in a large enterprise.

What is IMAP?
-------------
The Cyrus IMAP (Internet Message Access Protocol) server provides access to personal mail and system-wide bulletin boards through the IMAP protocol. The Cyrus IMAP server is a scalable enterprise mail system designed for use from small to large enterprise environments using standards-based technologies.

A full Cyrus IMAP implementation allows a seamless mail and bulletin board environment to be set up across multiple servers. It differs from other IMAP server implementations in that it is run on "sealed" servers, where users are not normally permitted to log in. The mailbox database is stored in parts of the filesystem that are private to the Cyrus IMAP system. All user access to mail is through software using the IMAP, POP3, or JMAP protocols.

The private mailbox database design gives the server large advantages in efficiency, scalability, and administrability. Multiple concurrent read/write connections to the same mailbox are permitted. The server supports access control lists on mailboxes and storage quotas on mailbox hierarchies.

IMAP Version 4 (IMAP4)
----------------------
The core technology used by Project Cyrus is the Internet Message Access Protocol (IMAP4). IMAP4 specifies a network protocol for accessing a remote message store from a client application. It is an Internet Standard (RFC 3501), and it is quickly gaining acceptance as the Internet standard for mail store access. Many major universities are basing their future distributed mail solutions on IMAP4. The previous versions of IMAP, IMAP2 and IMAP2bis are backward compatible with IMAP4 and are already in widespread use. There are already clients in existence on every major platform and many more in the works.

IMAP4 is an improvement over other popular Internet mail protocols when it comes to scale and availability. The Post Office Protocol (POP) family, and similar protocols, are less useful to a student-heavy user base, as they are designed to act primarily as store and forward engines. Clients contact a remote message store and download all their mail to a local message store. When the messages have been downloaded from the remote message store to the client, mobility becomes a real problem: The downloaded messages are no longer easily accessible from other clients. Even more importantly, many of the clients that students use have no permanent storage for their use, necessitating use of a remote filesystem for storage, which leads to problems with access and scale.

IMAP4 is a super-set of the functionality provided by POP3 -- that is, all the functionality of a POP3 client can be mimicked using the IMAP4 protocol. The IMAP4 revision of the IMAP protocol adds support for disconnected operation. This will allow for a client on a notebook computer to download portions of a mail store and keep them synchronized with the mail store over time.

Mime
-----
One of the goals of Project Cyrus is to support the MIME internet standard message interchange format. IMAP4 has rich support for MIME, allowing the MIME structure to be examined without downloading the whole message to the client and for individual MIME parts to be downloaded. For example, if a MIME message includes a 5meg audio portion and your client does not support audio, IMAP4 will allow all of the message to be downloaded with the exception of that MIME part. This is also important functionality for disconnected and slow link operation.

SMTP
-----
The Simple Mail Transport Protocol (SMTP) is the Internet standard for transporting mail. It is widely implemented and must be used by anyone who wants to communicate with the Internet community. SMTP is used solely for delivery of mail. It is not intended for dilail servers, gateways, and clients deliver mail to mail stores and gateways. SMTP is not intended for delivery of mail directly to clients. In addition, it is not wise to have clients deliver mail to the final destination in all cases. Often mail can not be delivered to the destination because of bad network connections, temporary machine downtime, or load problems at either end. In these cases the SMTP delivery agent must re-queue the mail and try again later. Since mail clients can be office machines which are not guaranteed to remain on or operational, it is not optimal for them to be delivering directly to remote destinations. To solve this, most mail clients deliver mail to post office machines which will deliver the mail on their behalf. Other reasons for this include better name resolution and error handling.

Project Cyrus uses SMTP as the protocol for mail transport. For internal use between Cyrus clients and Cyrus post office machines, Kerberos extensions have been added to SMTP to allow for better guarantees of the originator of the message. Some time in the future, the Kerberos extensions may be replaced or augmented by some form of Privacy Enhanced Mail (PEM), but that is not in the original scope of Project Cyrus.
