.. _faqs-o-annotations:

What annotations are available?
-------------------------------

Cyrus annotations are based on a draft
(http://tools.ietf.org/html/draft-daboo-imap-annotatemore-08) version of
:rfc:`5464`.

* **/admin** - Sets the administrator email address for the server. (See
  :cyrusman:`cyradm(1)`)

* **/check** - Boolean value "true" or "false" that indicates whether this
  mailbox should be checked at regular intervals by the client. The interval
  in minutes is specified by the ``/checkperiod`` entry. (Draft RFC)

* **/checkperiod** - Numeric value indicating a period of minutes that the
  client uses to determine the interval of regular 'new mail' checks for the
  corresponding mailbox. (Draft RFC)

* **/comment** - Sets a comment or description associated with the mailbox.
  (cyradm(1))

* **/motd** - Sets a "message of the day". The message gets displayed as an ALERT after authentication.

* **/sort** - Defines the default sort criteria [I-D.ietf-imapext-sort] to use
  when first displaying the mailbox contents to the user, or NIL if sorting is
  not required. (Draft RFC)

* **/thread** - Defines the default thread criteria [I-D.ietf-imapext-sort] to
  use when first displaying the mailbox contents to the user, or NIL if
  threading is not required. If both sort and thread are not NIL, then
  threading should take precedence over sorting. (Draft RFC)

* **/vendor/cmu/cyrus-imapd/condstore** - Enables the IMAP CONDSTORE extension
  (modification sequences) on the mailbox. (See :cyrusman:`cyradm(1)`)

* **vendor/cmu/cyrus-imapd/duplicatedeliver** - Flag signalling that we're
  allowing duplicate delivery of messages to the mailbox, overriding
  system-wide duplicate suppression.

* **/vendor/cmu/cyrus-imapd/expire** - Sets the number of days after which
  messages will be expired from the mailbox. (cyradm(1))

* **/vendor/cmu/cyrus-imapd/freespace** - Undocumented.

* **/vendor/cmu/cyrus-imapd/lastpop** - (time_t) of the last pop3 login to
  this INBOX, used to enforce the "poptimeout" imapd.conf option.

* **vendor/cmu/cyrus-imapd/lastupdate** - (time_t) of the last time a message
  was appended

* **/vendor/cmu/cyrus-imapd/news2mail** - Sets an email address to which
  messages injected into the server via NNTP will be sent. (cyradm(1))

* **/vendor/cmu/cyrus-imapd/partition** - Undocumented.

* **/vendor/cmu/cyrus-imapd/pop3newuidl** - Flag signalling that we're using
  "uidvalidity.uid" instead of just "uid" for the output of the POP3 UIDL
  command.

* **/vendor/cmu/cyrus-imapd/serve** - Undocumented.

* **/vendor/cmu/cyrus-imapd/sharedseen** - Enables the use of a shared \Seen
  flag on messages rather than a per-user \Seen flag. The ’s’ right in the
  mailbox ACL still controls whether a user can set the shared \Seen flag.
  (See :cyrusman:`cyradm(1)`)

* **/vendor/cmu/cyrus-imapd/shutdown** - Sets a shutdown message. The message
  gets displayed as an ALERT and all users are disconnected from the server
  (subsequent logins are disallowed). (cyradm(1))

* **/vendor/cmu/cyrus-imapd/sieve** - Indicates the name of the global sieve
  script that should be run when a message is delivered to the shared mailbox
  (not used for personal mailboxes). (cyradm(1))

* **/vendor/cmu/cyrus-imapd/size** - Undocumented.

* **/vendor/cmu/cyrus-imapd/squat** - Indicates that the mailbox should have a
  squat index created for it. (See :cyrusman:`squatter(8)`)
