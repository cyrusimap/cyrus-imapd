Authentication and Authorization
================================

The use of Cyrus IMAP may have a significant impact on the design, use and load of the current authentication and authorization infrastructure. In addition, authentication and authorization relates to both to security, and also, in the particular case of Cyrus IMAP, personal privacy.

Typically, an authentication and authorization database, such as for example LDAP, is already available and in use within an infrastructure. Cyrus IMAP would integrate with a variety of technologies, but a few considerations deserve outlining.

For example, when a user wants to set group permissions on an IMAP folder, the most intuitive attribute in LDAP to refer to the group is the Common Name (CN). This attribute however is not guaranteed to be unique. Uniqueness can be enforced within LDAP, although that may be too restrictive, and so the groups available in Cyrus IMAP can be limited to scope one, while the cn is used in the rdn (the cn is the naming attribute to compose the dn with); effectively enforcing uniqueness for those groups available to Cyrus IMAP.

Similarly, many deployments choose to use the mail LDAP attribute value as the mailbox name, while mail is a multi-valued attribute and is not configured to be enforced globally unique in the LDAP information tree under the root dn. In addition, attributes such as ``mailAlternativeAddress`` and/or alias could potentially hold the same value as anyone's mail attribute. These limitations or such implications become very clear when canonification of the authentication ID to the desired authorization ID is attempted.

For example, if ``jdoe`` is the login username, and Cyrus IMAP has a default realm configured ``example.org``, the authentication ID becomes ``jdoe@example.org``. It is this authentication ID, and not the supplied login username, that Cyrus IMAP uses to verify the credentials.

Cyrus IMAP thereafter allows authorization mechanisms, such as *ptclient* modules, to canonify the authentication ID to then ultimately return the authorization ID.

Suppose in the case of ``jdoe@example.org``, where the authentication ID had been set, an LDAP module for ptloader could search LDAP for a ``uid=%U`` (where ``%U`` is the local part of the authentication ID), find the mail attribute value is ``john.doe@example.org``, and authorize the user as such. Effectively, this enables Cyrus IMAP users to log in both with their username (uid) as well as their email address (or any of the aliases).

The process of client authentication and authorization


Client Authentication
---------------------

The exchange and verification of identity information provided by a client, otherwise known as *the process of authentication*, provides a set of credentials that allow the server to verify that the user is in fact the user, and not an imposter.

.. important::
    **Authentication != Authorization**

    Authentication and authorization are two separate processes. Authentication is about verifying the credentials supplied by the client, while authorization is the process of determining what rights the client has. Authentication, logically, preseeds authorization.

The most common set of credentials is a *username* and *password*, but other forms exist like Kerberos v5 ticket exchange (for which, to obtain such, most often a password is supplied), or certificate based authentication (the secret keys for which are most often locked with a passphrase). In any case, authentication works based on a shared secret, and/or a trusted source for verification. Kerberos v5 works based on shared secrets (keytab), and certificate based authentication works based on shared, trusted sources for verification.

In the case of usernames and passwords though, the exchange and verification of the credentials is at the basis of its security. Sending plain text usernames and passwords over the wire would not allow any application to verify the source of the credentials is actually the user &mdash; who is supposed to be the only party to know the unique combination of username and password.

To obfuscate the login credentials, authentication can be encrypted with CRAM-MD5 or DIGEST-MD5, but this requires the server to have a copy of the original, plain text password. The password in this case becomes the shared secret.

Another method is to allow the plain text username and password to be transmitted over the wire, but ensure Transport Layer Security (TLS) or the more implicit Secure Socket Layer (SSL). The plain text password can now be used to compare it against a SQL database, bind to an LDAP database, attempt PAM authentication with, etc.

Users and Mailboxes
-------------------

User mailboxes have a globally unique identifier which is not necessarily the same as the login name used. There are three distinguishable aspects to a user's entity and the mailbox associated with it;

The **user login credentials** that are associated with the user authentication entity and verify the user is who the user claims to be.

For example, the user logs in with username ``john.doe@example.org`` and password ``verysecret``.

The **user's authentication entity** &mdash; with all attributes associated with it &mdash; can have one of those attributes be used to create the relationship between the user authentication entity on the one side, and the mailbox entity on the other side.

For example, the user that authenticated as ``john.doe@example.org`` may have a mailbox named ``jdoe``.

The **authorization entity**, used to assign certain permissions to the user, uses the same attribute used to determine the mailbox name.

For example, the user that authenticated as ``john.doe@example.com`` and has mailbox ``jdoe`` needs an access control list entry on that mailbox that assigns ``jdoe`` certain rights on said mailbox.

