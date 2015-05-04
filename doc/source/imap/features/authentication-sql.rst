==================
SQL Authentication
==================

Pre-requisites
==============

All examples use MySQL but it should be possible to use PostgresQL or similar database.

MySQL Server
------------
This document assumes that MySQL is running on ``localhost`` and that you can connect as a user who has the required privileges to add users and databases.

We will create a database ``db_mail`` with the ``mail_users`` table and grant SELECT privileges to the user ``db_mail_user`` with password ``db_mail_password``

The database connection details are completely changeable and you can even use a remote MySQL server, but remember to change them throughout the instructions below.

.. note::
    The database table doesn't need to be writable by the Cyrus server. If your master database is held on a different server, you could use MySQL replication to replicate just the mail_users table to the Cyrus server and make the table read-only on the replica.

saslauthd
---------
saslauthd needs to be configured to use PAM. In the output of :command:`ps ax | grep saslauthd` it'll probably look like :command:`saslauthd -a pam`
Optionally ``-r`` (realm) parameter with saslauthd if you plan to use username@domain style logins instead of just username

pam_mysql
---------
pam_mysql (0.7) from http://pam-mysql.sourceforge.net/ - it's quite likely that other MySQL PAM modules would work, but this one definitely works and using a different version will require different configuration to that described below.

Database structure
==================

At the very minimum, the mail_users table requires username and password columns. It is also recommended to include a column to indicate if the account is permitted to login or not since this will make disabling an account much easier than altering the password field.

.. parsed-literal::
    CREATE DATABASE db_mail;
    GRANT SELECT ON db_mail.* TO 'db_mail_user'@'localhost'
        IDENTIFIED BY 'db_mail_password';

    USE db_mail;

    CREATE TABLE mail_users (
        username VARCHAR(200) NOT NULL,
        password VARCHAR(40) NOT NULL,
        active TINYINT(1) NOT NULL DEFAULT 1,
        INDEX username_idx(username)
    );

Next insert an example record for testing purposes. The username must match the mailbox created in Cyrus and the login is the full email address. If you don't need/want domain based virtual users, you can also just insert a username without the @example.org

.. parsed-literal::

    INSERT INTO mail_users SET username='jane@example.org',
        password=ENCRYPT('janepass','$1$1234abcd'), active=1;

.. warning::
    You should use better passwords and salts in production!

On modern versions of Linux, the salts used for the password encryption should be $1$ followed by 8 random alphanumeric characters. Other operating systems may have different requirements for the salt as used by the system crypt(3) function and described in the relevant man page.

PAM configuration for use with saslauthd
========================================

Assuming both POP3 and IMAP services are being offered, you will need to update /etc/pam.d/pop and /etc/pam.d/imap to allow MySQL to be used.

Assuming the files already contain the following

.. parsed-literal::

    #%PAM-1.0
    auth       required     pam_nologin.so
    auth       include      system-auth
    account    include      system-auth
    session    include      system-auth

amend them to read

.. parsed-literal::

    #%PAM-1.0
    auth       required     pam_nologin.so
    auth       sufficient   pam_mysql.so config_file=/etc/mail-pam-mysql.conf
    auth       include      system-auth
    account    sufficient   pam_mysql.so config_file=/etc/mail-pam-mysql.conf
    account    include      system-auth
    password   required     pam_deny.so
    session    include      system-auth

The configuration file specified also needs to be created. Using the database connection details established earlier, the configuration file should contain:

.. parsed-literal::

    verbose = 0;
    users.host = localhost;
    users.database = db_mail;
    users.db_user = db_mail_user;
    users.db_passwd = db_mail_password;
    users.password_crypt = 1;
    users.md5 = true;
   
    users.table = mail_users;
    users.where_clause = active = 1;
    users.user_column = username;
    users.password_column = password;

.. warning::
    Because this file contains the database password, you should ensure it is properly protected. Change the ownership to root:root (if it's not already), and :command:`chmod 600 /etc/mail-pam-mysql.conf`

Changing verbose to 1 results in a large amount of debugging output in the logs, including the SQL being run. This can be useful if it's not working as expected.
If you are using the MySQL PASSWORD() function, change password_crypt to 1


Testing the SASL configuration
==============================

If everything is correct, you should be able to run the following commands:

.. parsed-literal::

    $ :command:`testsaslauthd -u jane -r example.org -p janepass -s imap`
    0: OK "Success."

    $ :command:`testsaslauthd -u jane -r example.org -p janepas3 -s imap`
    0: NO "authentication failed"

    $ :command:`testsaslauthd -u jane -r example.org -p janepass -s pop`
    0: NO "authentication failed"

This fails because we haven't setup the PAM config file for the POP service, update /etc/pam.d/pop by adding the following two 'sufficient' lines above the appropriate 'required' lines.

.. parsed-literal::
   auth       sufficient   pam_mysql.so config_file=/etc/mail-pam-mysql.conf
   account    sufficient   pam_mysql.so config_file=/etc/mail-pam-mysql.conf

If everything is correct, you should be able to run the following and get an OK response.

.. parsed-literal::
    $ :command:`testsaslauthd -u jane -r example.org -p janepass -s pop`
    0: OK "Success."

Create the test mailboxes within Cyrus
======================================

.. parsed-literal::
    cyradm> cm user/jane@example.org

If you get an error when creating the mailbox, check that you have ``virtdomains: userid`` and ``unixhierarchysep: on`` in /etc/imapd.conf as the syntax for the mailbox name will be different.

Testing everything together
===========================

This step assumes Cyrus is already configured and listening on localhost port 143 (IMAP). Change the openssl command as required if it's not.

.. parsed-literal::

    $ :command:`openssl s_client -connect localhost:143 -starttls imap`
    ...
    . OK Completed
    0 LOGIN jane@example.org janepass
    0 OK [CAPABILITY ...] User logged in ...
    0 LOGOUT
    * BYE LOGOUT received
    0 OK Completed

If you don't get an OK response to the LOGIN command, something isn't working properly and there may be useful log messages in either maillog, messages or secure log files.

The completion of this part of the documentation is pending the
resolution of :task:`68`.

Back to :ref:`imap-features`
