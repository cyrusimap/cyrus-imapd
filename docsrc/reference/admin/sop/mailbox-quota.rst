Mailbox Folders exempt from quota
---------------------------------

By creating an additional quota root, a folder's contents can be made exempt from counting towards the mailbox's quota.

.. note::
    Making an INBOX/Archive/ Folder exempt from quota: ::

        cyradm> createmailbox user/john.doe@example.org
        cyradm> setquota user/john.doe@example.org 2097152
        cyradm> listquotaroot user/john.doe@example.org
        cyradm> createmailbox user/john.doe/Archive@example.org
        cyradm> setquota user/john.doe/Archive@example.org
        cyradm> listquotaroot user/john.doe/Archive@example.org


