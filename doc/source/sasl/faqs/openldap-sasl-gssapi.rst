How do I configure OpenLDAP +SASL+GSSAPI?
-----------------------------------------

This article assumes that you have read and followed the SASL chapter of the `OpenLDAP Administrator's Guide <http://www.openldap.org/doc/admin24/sasl.html>`_. You should have a Kerberos server installed (such as Heimdal or MIT), and created all the appropriate principals (client and service) necessary.

To verify that you have the Cyrus GSSAPI mechanism properly installed, use the pluginviewer command. For instance::

    server:~# pluginviewer  | grep -i gssapi
     CRAM-MD5 PLAIN NTLM GSSAPI OTP DIGEST-MD5 ANONYMOUS LOGIN EXTERNAL 
    Plugin "gssapiv2" [loaded],     API version: 4         
           SASL mechanism: GSSAPI, best SSF: 56, supports setpass: no 
    CRAM-MD5 PLAIN NTLM GSSAPI OTP DIGEST-MD5 ANONYMOUS LOGIN EXTERNAL 
    Plugin "gssapiv2" [loaded],     API version: 4         
           SASL mechanism: GSSAPI, best SSF: 56 

Both your server and client systems will need to have this mechanism installed. If not, you may find the mechanism located in a binary package that you do not yet have installed, or you may need to recompile your Cyrus SASL installation.

On your client system, search the Root DSE of the server to view advertised mechanisms::

    client:~# ldapsearch -LLL -x -H ldap://ldap.example.org -s "base" -b "" supportedSASLMechanisms 
    dn: 
    supportedSASLMechanisms: DIGEST-MD5 
    supportedSASLMechanisms: NTLM 
    supportedSASLMechanisms: GSSAPI 
    supportedSASLMechanisms: OTP 
    supportedSASLMechanisms: CRAM-MD5

If you received a No Such Object error, you may have an `ACL misconfiguration on your server <http://www.openldap.org/doc/admin24/appendix-common-errors.html#ldap_sasl_interactive_bind_s>`_.

If you do not see GSSAPI listed, verify that the server can read the appropriate keytab. The default is ``/etc/krb5.keytab`` and is typically only readable by the root user. If your Kerberos library supports it, you can create a keytab in an alternate location, such as ``/etc/krb5.keytab-ldap``, with only your LDAP service principal, and read permissions for your OpenLDAP user.

If your OpenLDAP server is looking for an unexpected principal within your keytab, use sasl-host and sasl-realm to influence which principal it will use (see the slapd.conf man page).

For more control over how the SASL library operates within the OpenLDAP? server, you can create a slapd.conf SASL configuration. This is not the same configuration file as the OpenLDAP configuration (slapd.conf). The location of this file is dependent how on Cyrus SASL was compiled (via the ``--with-plugindir`` option during configure). It is the directory where your plugins are installed.

For instance, if you create /usr/lib/sasl2/slapd.conf (assuming that is the correct location on your system) with the following contents::

    keytab: /etc/krb5.keytab-ldap 
    mech_list: CRAM-MD5 DIGEST-MD5 GSSAPI 

then the server will search within /etc/krb5.keytab-ldap when initializing the GSSAPI plugin. The server will only offer the mechanisms listed in mech_list. If mech_list is not specified, the server will offer all the mechanisms available, and that it can initialize.

Once you have verified that the server is advertising GSSAPI support, then try::

    client:~# ldapsearch -LLL -Y GSSAPI -H ldap://ldap.example.org -s "base" -b "" supportedSASLMechanisms 
    SASL/GSSAPI authentication started 
    SASL username: host/client.example.org@EXAMPLE.ORG 
    SASL SSF: 56 SASL data security layer installed. 
    dn: 
    supportedSASLMechanisms: DIGEST-MD5 
    supportedSASLMechanisms: NTLM 
    supportedSASLMechanisms: GSSAPI 
    supportedSASLMechanisms: OTP 
    supportedSASLMechanisms: CRAM-MD5 

If you receive a list of mechanisms, then congratulations, you're done.

If instead you receive an error, then it's possible that your client is requesting a service principal that mismatches what your server is using.

Verify that you have received a TGT ticket from your kerberos server, and that you have also received a service principal ticket for the server (e.g. ldap/ldap.example.org@EXAMPLE.ORG). Use klist to verify::

    client:~# klist
    Credentials cache: FILE:/tmp/krb5cc_0
           Principal: host/client.example.org@EXAMPLE.ORG
     Issued           Expires          Principal
    Feb 22 11:00:02  Feb 22 21:00:01  krbtgt/EXAMPLE.ORG@EXAMPLE.ORG
    Feb 22 11:24:39  Feb 22 21:00:01  ldap/ldap.example.org@EXAMPLE.ORG

If not, then a network capture utility, such as wireshark, offers a good way to show you which service principal your client is requesting, and what errors are being returned by the server.

If you wish to also view the interaction with the LDAP server with a capture utility, you will need to negotiate a SASL layer without encryption. You can specify ``-O maxssf=1`` in your client side command (ldapwhoami, ldapsearch etc.), e.g.::

    client:~# ldapsearch -LLL -Y GSSAPI -H ldap://ldap.example.org -O maxssf=1 -s "base" -b "" supportedSASLMechanisms 

You might find it easier to specify defaults on your client system, to keep your commands shorter. See the man page for ldap.conf for details. You can specify the default server in your ldap.conf file::

    URI    ldap://ldap.example.org 

And you can specify the default mechanism in ~/.ldaprc (in your home directory):

    ASL_MECH GSSAPI 
    