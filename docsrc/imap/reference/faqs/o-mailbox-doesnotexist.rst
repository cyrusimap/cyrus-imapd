Cyrus delivers claims that the mailbox does not exist 
-----------------------------------------------------

Given that you have a username ``john@domain.tld``, unless you 
escape the '@' as explained below, Cyrus deliver will claim 
that the mailbox does not exist.

Instead of
``deliver john@domain.tld``
you should be using
``deliver john\\\@domain.tld``.

And instead of
``deliver -a john@domain.tld -m user/john@domain.tld``
you should be using
``deliver -a john\@domain.tld -m user/john\\\@domain.tld``

As far as the '@' is concerned, the same applies while not 
using the unixhierarchysep.

keywords: cyrdeliver master.cf
