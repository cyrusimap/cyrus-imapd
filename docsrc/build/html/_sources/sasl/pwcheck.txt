SASL Pwcheck
============

Auxprop
-------

Auxprop-hashed
--------------

Saslauthd
---------

**What is saslauthd?** saslauthd is a daemon which validates

``ldap_servers`` - ``ldap://localhost``

    Specify a space separated list of LDAP server URIs of the form **ldap[si]://[name[:port]]**. See the ``ldap.conf`` *URI* option for formatting details.

``ldap_bind_dn`` - none

    When simple authentication is desired, specify a distinguished name to use for a simple authenticated bind or a simple unauthenticated bind. Do not specify if an anonymous bind is desired. This option is ignored when the evaluated ``ldap_auth_method`` is ``fastbind``.

``ldap_bind_pw`` - none

    ``ldap_bind_pw`` is an alias for ``ldap_password``.

``ldap_password`` - none

    When simple authentication is desired, specify a password to perform an authenticated bind, or do not specify for an unauthenticated or anonymous bind. When SASL authentication is desired, specify a password to use where required by the underlying SASL mechanism. This option is ignored when the evaluated ``ldap_auth_method`` is ``fastbind``.

``ldap_version`` - 3

    Defaults to version *3*. If ``ldap_use_sasl`` or ``ldap_start_tls`` are enabled, this option will be ignored, and will conform to the default value. Version *3* **is** compatible with anonymous binds, simple authenticated binds and simple unauthenticated binds. Version *2* should only be necessary where required by the server.

``ldap_search_base`` - none

    When ``ldap_auth_method`` is evaluated as *bind*, ``ldap_search_base`` will be used to search for the user's distinguished name. When ``ldap_auth_method`` is *custom*, ``ldap_search_base`` will be used to find the user's ``ldap_password_attr`` attribute. When ``ldap_auth_method`` is evaluated as *fastbind*, ``ldap_search_base`` is ignored. If ``ldap_search_base`` contains substitution tokens, they will be replaced as specified in the ``ldap_filter`` token expansion rules.

``ldap_filter`` - uid=%u

    When ``ldap_auth_method`` is evaluated as *bind*, ``ldap_filter`` will be used to search for the user's distinguished name. When ``ldap_auth_method`` is *custom*, ``ldap_filter`` will become, after token expansion, the user's distinguished name. When ``ldap_auth_method`` is evaluated as *fastbind*, ``ldap_filter`` is ignored.

    The following tokens, when contained within the ``ldap_filter`` option, will be substituted with the specified values:

    ``%%``

        is replaced with a literal %.

    ``%u``

        is replaced with the userid to be authenticated.

    ``%U``

        is replaced by the portion of the userid before the first @ character. If an @ character does not exist in the userid, then ``%U`` would function identically to ``%u``. For example, if the userid to be authenticated is *jsmith@example.org*, ``%u`` would be replaced by *jsmith@example.org* and ``%U`` would be replaced by *jsmith*.

    ``%d``

        is replaced by the portion of the userid after the first @ character. If an @ character does not exist in the userid, ``%d`` will be replaced by the ``realm`` value passed to ``saslauthd``. If no ``realm`` value was passed to saslauthd, ``%d`` will be replaced by the configured ``ldap_default_realm``, or by an empty string if ``ldap_default_realm`` is not configured.

    ``%1-9``

        Within a userid which contains an @ character, followed by a domain name, ``%1`` will be replaced by the top level domain, ``%2`` will be replaced by the secondary domain, ``%3`` will be replaced by the tertiary domain, up to and including ``%9`` which would be replaced by the ninth level domain. If no @ character exists in the userid, or if there is no domain name after the @ character, or if the specified hierarchical domain level does not exist, the option is replaced by the ``realm`` value passed to ``saslauthd``. Should no ``realm`` value exist in those scenarios, the option is replaced by the configured ``ldap_default_realm``, or by an empty string if ``ldap_default_realm`` has not been configured.

        For example, if the userid to be authenticated is *jsmith@example.org*, ``%1`` would be replaced by *org* and ``%2`` would be replaced by *example*.

    ``%s``

        is replaced by the ``service`` option passed to ``saslauthd``, or by an empty string if no ``service`` option was passed.

    ``%r``

        is replaced by the ``realm`` option passed to ``saslauthd``. If no ``realm`` value was passed to saslauthd, ``%r`` will be replaced by the configured ``ldap_default_realm``, or by an empty string if ``ldap_default_realm`` is not configured.

``ldap_password_attr`` - userPassword

    When ``ldap_auth_method`` is evaluated as *custom*, ``ldap_password_attr`` specifies an attribute that will be requested and retrived. If successfully retrived, the authentication request will succeed if the ``ldap_password_attr`` attribute contains a supported password hash, and if the user submitted password matches the hash. When ``ldap_auth_method`` is *bind* or *fastbind*, ``ldap_password_attr`` is ignored.


``ldap_group_dn`` - none

    If ``ldap_group_dn`` is specified, group authorization must also succeed (in addition to the prior authentication step), for the user's authentication attempt to be successful. If ``ldap_group_dn`` contains substitution tokens, they will be replaced as specified in the ``ldap_filter`` token expansion rules. One additional token substitution is applicable to ``ldap_group_dn``:

    ``%D``

        is replaced by the distinguished name that was specified, or evaluated, in the authentication step. If ``ldap_use_sasl`` is enabled, the distinguished name will be resolved by performing an ldapwhoami extended operation after a successful authentication. If ``ldap_group_dn`` is specified and ``ldap_use_sasl`` is enabled, but the ldap server does not support the ldapwhoami extended operation, or if the ldapwhoami extended operation fails, then the user's authentication attempt is unsuccessful.


``ldap_group_attr`` - uniqueMember

    ``ldap_group_attr`` is ignored unless ``ldap_group_dn`` is also specified and ``ldap_group_match_method`` is *attr*. ``ldap_group_attr`` specifies an attribute which contains the authenticating identity's dinstinguished name. See the ``ldap_group_match_method`` entry for additional details.

``ldap_group_filter`` - none

``ldap_group_search_base`` - defaults to the evaluated ``ldap_search_base``

``ldap_group_scope`` - *sub*

``ldap_group_match_method`` - attr

``ldap_default_realm`` - none

``ldap_default_domain`` - none

    ``ldap_default_domain`` is an alias for ``ldap_default_realm``.

``ldap_auth_method`` - bind

``ldap_timeout`` - 5

``ldap_size_limit`` - 1

``ldap_time_limit`` - 5

``ldap_deref`` - never

``ldap_referrals`` - no

``ldap_restart`` - yes

``ldap_scope`` - sub

``ldap_use_sasl`` - no

``ldap_id`` - none

``ldap_sasl_authc_id`` - none

``ldap_authz_id`` - none

    Does not make any sense to supply an authz identity when performing sasl/fastbind.

``ldap_sasl_authz_id`` - none

    ``ldap_sasl_authz_id`` is an alias for ``ldap_authz_id``.

``ldap_realm`` - none

``ldap_sasl_realm`` - 

``ldap_mech`` - 

    It doesn't make any sense to use a mech that does not require an authname and password, when using fastbind.

``ldap_sasl_mech`` - 

``ldap_sasl_secprops`` - 

``ldap_start_tls`` - 

``ldap_tls_check_peer`` - 

``ldap_tls_cacert_file`` - 

``ldap_tls_cacert_dir`` - 

``ldap_tls_ciphers`` - 

``ldap_tls_cert`` - 

``ldap_tls_key`` - 

``ldap_debug`` - 

Authdaemon
----------

Alwaystrue
----------

Auto Transition
---------------


