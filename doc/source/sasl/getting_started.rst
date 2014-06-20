Getting Started
===============

SASL
----

Simple Authentication and Security Layer (SASL) is a protocol developed by the Internet Engineering Task Force (IETF) for the purpose of providing an extensible and pluggable authentication framework, primarily for non-web related protocols. It is commonly used in email related protocols, such as SMTP, IMAP, and POP, along with XMPP, LDAP, and a few others. In doing so, various implementations of those protocols, such as the Cyrus IMAP or Dovecot servers, can support a wide range of authentication mechanisms with various email clients which implement the IMAP protocol, including Thunderbird, Outlook, and the Android mail client.

RFC 4422 is the base framework specification for SASL. It provides guidance for protocol designers, server software implementations, and SASL mechanism designers. Protocol definitions, and SASL mechanism specifications in turn make use of this framework to independently support each other. That is, if a protocol were designed 5 years ago to make use of SASL, and a new mechanism were designed today, server implementations and client software could make use of that new mechanism without a change to the original server protocol spec.

SASL Authentication Mechanisms
------------------------------

SASL mechanisms are plugable authentication methods that are developed independently of server protocols. For example, the Generic Security Service Application Program Interface (GSSAPI) mechanism, defined in RFC 4752, defines a network oriented protocol for authenticating a client to a server, using Kerberos version 5, a trusted 3rd party ticket based system. The GSSAPI mechanism should work with all clients and servers which implement support for it, regardless of the actual server protocol used (such as IMAP), given the protocol was designed for use with the SASL framework.

A list of developed SASL mechanisms can be found at the `IANA registered SASL mechanisms <http://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xml>`__ page. A more detailed discussion of these mechanisms can be found in :doc:`Authentication Mechanisms<authentication_mechanisms>`.

Security Layers
---------------

SASL Security Layers allow a server and client to negotiate integrity and confidentiality protection for a connection once it has been authenticated. It is only available for mechanisms which themselves are capable of providing such protection (such as GSSAPI). It is capable of being used to encrypt a connection over the public internet, and can be used as an alternative to TLS encryption.

Channel Binding
---------------

.. todo::
   What's channel binding?

Realms
------

.. todo::
   What are realms?

Protocols
---------

.. todo::
   What protocols?

Cyrus SASL
----------

.. todo::
   Something required here

The Glue Library
----------------

.. todo::
   A bit stuck with this one too :)

Auxiliary Properties
--------------------

.. todo::
   More properties...

Plugins
-------

.. todo::
   Plugins, plugins and plugins
