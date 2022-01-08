Integration with Sendmail
_________________________
Objectives
##########
This manual describes how to integrate Sendmail with Cyrus IMAP.  `Open Sendmail <http://open-sendmail.sourceforge.net>`_ presents alternative approaches, but these do not integrate well with email addresses from virtual domains, which are hosted by Cyrus IMAP, but are not in the `virtuser` table.

Cyrus IMAP can manage many domains.  It has a default domain, and other, virtual domains.

Sendmail can also manage many domains.  Its primary domains are stored in the `w` class and are read from `/etc/mail/local-host-names`.  The rewritings for these domains are modified using the aliases database.  Sendmail handles unqualified email addresses and addresses from the domains in the `w` class the same. Sendmail in addition can manage further, virtual domains by defining the `VirtHost` class.  The redirections for the virtual domains are controlled by `virtusertable`.

This guide explains how to configure sendmail, so that it handles unqualified email addresses in the same way, as if they were in the default Cyrus IMAP domain.  It assumes, that the default Cyrus domain is in the `w` class.  At the end it will be possible to have destination addresses with domains in the `w` or `VirtHost` classes and these addresses will be delivered to Cyrus IMAP after aliases and `virtusertable` rewritings, if and only if Cyrus IMAP hosts them.

Sendmail will be configured to verify using `smmapd` if Cyrus does have a mailbox, and reject the email during the SMTP dialog otherwise.  This avoids sending bounces.  Bounces reduce the IP reputation of a mail server.  If a local for the server user does not have a Cyrus IMAP account, this user will not get its emails in a folder on the server.  If `smmapd` does not respond, sendmail will accept emails for any address.

If a virtual mailbox exists in Cyrus IMAP and `virtusertable` redirects the emails for that mailbox somewhere, the `virtusertable` takes precedence, like the aliases database has precedence in such cases.

The user database is not considered in this guide.

Plus addressing works, when the destination folder does exist and is lowercased:  If `user1` has folders `abc` and `mNp`, emails for `user1+abc` and `user1+aBc` will be accepted, emails for `user1+mNp` and `user1+mnp` will be rejected.  The lowercase limitation comes from `smmapd`.  Emails for `user1+def` will be rejected, if `user1` has no mailbox `def`, even if a Sieve script would place such mails in existing folders.

Plus addressing does not survive aliases rewriting.  If the aliases table contains `user2: user1`, emails for `user2+abc` will be rejected, while emails for `user2` or `user1+abc` will be accepted.  After inserting `user2+abc: user1+abc` in the aliases table, emails for `user2+abc` will be accepted.

Install Sendmail
################

We'll set up LMTP with the Sendmail SMTP server.

::

    sudo apt-get install -y sendmail

Add cf/feature/anfi_vcyrus.m4
#############################
Create the file cf/feature/anfi_vcyrus.m4:

.. code-block:: m4

  divert(-1)
  dnl
  dnl By using this file, you agree to the terms and conditions set
  dnl forth in the LICENSE file which can be found at the top level of
  dnl the sendmail distribution (sendmail-8.12).
  dnl
  dnl     Contributed by Andrzej Filip and Dilyan Palauzov
  LOCAL_CONFIG
  # cyrus - map for checking cyrus maibox presence
  Kcyrus socket -T<TMPF> -a<OK> local:/var/imap/socket/smmapd
  
  LOCAL_RULESETS
  SLocal_localaddr
  R$+     $: $1 $| $(cyrus $1 $: $)
  R$+ $|		$#error $@ 5.1.1 $: "550 User unknown."
  R$+ $| $*<TMPF>	$#error $@ 4.3.0 $: "451 Temporary system failure. Please try again later."
  R$+ $| $*<OK>		$#cyrusv2 $@ $: $1
  R$+ $| $*		$: $1

Many spaces in a row stand for the tabulator character.

Despite the naming confusion, Cyrus 3 works with the `cyrusv2` mailer.

This file creates a map called `cyrus`, which connects to the Cyrus` `smmapd` service.

The file extends the `localaddr=5` and `Local_localaddr` rulesets to verify whether an address is known to Cyrus IMAP.  The rulesets are called from the `local` mailer, as the `local` mailer has the `5` mailer flag set.  The ruleset changes the mailer to `cyrusv2` and the email is accepted if and only if the address is known to Cyrus IMAP.

The temporary rejections do not work in practice.  If `smmapd` is down, the email is queued instead of being rejected.  The 451 line above is there to encourage discussion.

Patching m4/proto.m4
####################
.. code-block:: diff

  diff --git a/cf/m4/proto.m4 b/cf/m4/proto.m4
  --- a/cf/m4/proto.m4
  +++ b/cf/m4/proto.m4
  @@ -1147,6 +1147,10 @@ dnl if no match, change marker to prevent a second @domain lookup
   R<@> $+ + $* < @ $+ . >	$: < $(virtuser @ $3 $@ $1 $@ $2 $@ +$2 $: ! $) > $1 + $2 < @ $3 . >
   dnl without +detail
   R<@> $+ < @ $+ . >		$: < $(virtuser @ $2 $@ $1 $: @ $) > $1 < @ $2 . >
  +dnl If a virtual address is not in the virtusertable, but cyrus knows about the address, deliver it.
  +R< error : $-.$-.$- : $+ > $+ < @ $={VirtHost} . >		$: < error : $1.$2.$3 : $4 > $5 < $6 . > $| $(cyrus  $5@$6 $: $)
  +R< error : $-.$-.$- : $+ > $* < $* . > $| $*<OK>		$#cyrusv2 $@ $: $5@$6
  +R< error : $-.$-.$- : $+ > $* $| $*<TMPFS>		$#error $@ 4.3.0 $: "451 Temporary system failure. Please try again later."
   dnl no match
   R<@> $+				$: $1
   dnl remove mark

Where many spaces in a row stand for the tabulator key.

If an address from a virtual domain is not found in the `virtusertable`, ask `smmapd` if the address is known to Cyrus IMAP.  If it is known, deliver it to Cyrus IMAP.

Patching mailer/cyrusv2.m4
##########################

.. code-block:: diff

  diff --git a/cf/mailer/cyrusv2.m4 b/cf/mailer/cyrusv2.m4
  --- a/cf/mailer/cyrusv2.m4
  +++ b/cf/mailer/cyrusv2.m4
  @@ -11,7 +11,7 @@ PUSHDIVERT(-1)
   #
   
   _DEFIFNOT(`_DEF_CYRUSV2_MAILER_FLAGS', `lsDFMnqXz')
  -_DEFIFNOT(`CYRUSV2_MAILER_FLAGS', `A@/:|m')
  +_DEFIFNOT(`CYRUSV2_MAILER_FLAGS', `8m')
   ifdef(`CYRUSV2_MAILER_ARGS',, `define(`CYRUSV2_MAILER_ARGS', `FILE /var/imap/socket/lmtp')')
   define(`_CYRUSV2_QGRP', `ifelse(defn(`CYRUSV2_MAILER_QGRP'),`',`', ` Q=CYRUSV2_MAILER_QGRP,')')dnl
 

The `8` flag means, that Cyrus LMTPd can accept 8bit data and sendmail will not convert 8bit data to 7bit before passing it to Cyrus IMAP.  The `A@/:|` functionality will be performed by the `local` mailer, before the `cyrusv2` mailer is called.  The `cyrus2v` mailer is used only to pass data to Cyrus IMAP, after it is verified, that Cyrus IMAP hosts a particular mailbox.  Thus the `cyrus2v` mailer does not call the `localaddr=5` rule set in order to avoid loops. (If the `cyrusv2` mailer calls the `localaddr=5` ruleset and the `localaddr=5` ruleset calls the `cyrusv2` mailer, there is an endless loop).

The patch to `m4/proto.m4` also requires a mailer, which does not call the `localaddr=5` ruleset.  Because of this, substituting the `local` mailer by `define(\`confLOCAL_MAILER', \`cyrusv2')dnl` will not work.  The proposed setup needs one mailer calling the `localaddr=5` ruleset (here the `local` mailer) and one mailer not calling the `localaddr=5` ruleset (the `cyrusv2` mailer).

Sendmail communication
######################

For LMTP and SMMAP to work with Sendmail, it is necessary to create a folder that will contain the UNIX socket used by Sendmail and Cyrus to deliver/receive emails:

::

    sudo mkdir -p /var/run/cyrus/socket
    sudo chown cyrus:mail /var/run/cyrus/socket
    sudo chmod 750 /var/run/cyrus/socket

Do the same for the `smmapd` socket.

Adjustments for the `.mc` files
###############################
In your `.mc` files add::

  FEATURE(`anfi_vcyrus')dnl
  MAILER(`cyrusv2')dnl

and recompile them, e.g. by calling `make file.cf` to convert `file.mc` to `file.cf`.  Test with::

  # ggg is unqualified address, which exists both in Cyrus’ default domain and in sendmails’ w class
  $ sendmail -C file.cf -bv ggg
  ggg... deliverable: mailer cyrusv2, user ggg
  
  # verify that ggg and ggg@your-primary-domain resolve in the same way, your-primary-domain is the default Cyrus IMAP domain
  $ sendmail -C file.cf -bv ggg@your-primary-domain
  ggg... deliverable: mailer cyrusv2, user ggg
  
  # as above, but here another-domain belongs to class `w` and it is not the default domain for Cyrus IMAP
  $ sendmail -C file.cf -bv ggg@another-domain
  ggg... deliverable: mailer cyrusv2, user ggg

  # for an address, which exists in Cyrus IMAP, and is not overwritten in virtusertable.
  # domain1.org belongs to class VirtHost and does not belong to class w.
  $ sendmail -C sendmail-mail.cf -bv zzz@domain1.org
  zzz@domain1.org... deliverable: mailer cyrusv2, user zzz@domain1.org
