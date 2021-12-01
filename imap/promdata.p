# Prometheus metric definitions file
#
# metric <type> <name> <description>
#   * type is one of "counter" or "gauge"
#   * name must be [a-z0-9_] only
#   * description is free text until EOL but don't be silly
#
# label <metric> <key> <values...>
#   * metric is the name of an already defined metric
#   * key must be [a-z0-9_] only
#   * values must be [a-z0-9_] only and are whitespace delimited until EOL
#
# Each metric may have zero or one labels applied to it
#
# '#' begins a comment
#
# There is not currently a line-continuation character supported by the parser,
# so this file will contain long lines!

metric counter cyrus_imap_connections_total             The total number of IMAP connections
metric gauge   cyrus_imap_active_connections            The number of currently active IMAP connections
metric gauge   cyrus_imap_ready_listeners               The number of currently ready IMAP listeners
metric counter cyrus_imap_shutdown_total                The number of IMAP process shutdowns
    label cyrus_imap_shutdown_total status ok error
metric counter cyrus_imap_append_total                  The total number of IMAP APPENDs
metric counter cyrus_imap_authenticate_total            The total number of IMAP AUTHENTICATEs
    label cyrus_imap_authenticate_total result yes no
metric counter cyrus_imap_capability_total              The total number of IMAP CAPABILITYs
metric counter cyrus_imap_compress_total                The total number of IMAP COMPRESSs
metric counter cyrus_imap_check_total                   The total number of IMAP checks
metric counter cyrus_imap_copy_total                    The total number of IMAP COPYs
metric counter cyrus_imap_create_total                  The total number of IMAP CREATEs
metric counter cyrus_imap_close_total                   The total number of IMAP CLOSEs
metric counter cyrus_imap_delete_total                  The total number of IMAP DELETEs
metric counter cyrus_imap_deleteacl_total               The total number of IMAP DELETEACLs
metric counter cyrus_imap_dump_total                    The total number of IMAP DUMPs
metric counter cyrus_imap_expunge_total                 The total number of IMAP EXPUNGEs
metric counter cyrus_imap_examine_total                 The total number of IMAP EXAMINEs
metric counter cyrus_imap_fetch_total                   The total number of IMAP FETCHs
metric counter cyrus_imap_getacl_total                  The total number of IMAP GETACLs
metric counter cyrus_imap_getannotation_total           The total number of IMAP SETANNOTATIONs
metric counter cyrus_imap_getmetadata_total             The total number of IMAP GETMETADATAs
metric counter cyrus_imap_getquota_total                The total number of IMAP GETQUOTAs
metric counter cyrus_imap_getquotaroot_total            The total number of IMAP GETQUOTAROOTs
metric counter cyrus_imap_genurlauth_total              The total number of IMAP GENURLAUTHs
metric counter cyrus_imap_id_total                      The total number of IMAP IDs
metric counter cyrus_imap_idle_total                    The total number of IMAP IDLEs
metric counter cyrus_imap_logout_total                  The total number of IMAP LOGOUTs
metric counter cyrus_imap_list_total                    The total number of IMAP LISTs
metric counter cyrus_imap_lsub_total                    The total number of IMAP LSUBs
metric counter cyrus_imap_listrights_total              The total number of IMAP LISTRIGHTSs
metric counter cyrus_imap_myrights_total                The total number of IMAP MYRIGHTSs
metric counter cyrus_imap_mupdatepush_total             The total number of IMAP MUPDATEPUSHs
metric counter cyrus_imap_starttls_total                The total number of IMAP STARTTLSs
metric counter cyrus_imap_store_total                   The total number of IMAP STOREs
metric counter cyrus_imap_select_total                  The total number of IMAP SELECTs
metric counter cyrus_imap_search_total                  The total number of IMAP SEARCHs
metric counter cyrus_imap_subscribe_total               The total number of IMAP SUBSCRIBEs
metric counter cyrus_imap_setacl_total                  The total number of IMAP SETACLs
metric counter cyrus_imap_setannotation_total           The total number of IMAP SETANNOTATIONs
metric counter cyrus_imap_setmetadata_total             The total number of IMAP SETMETADATAs
metric counter cyrus_imap_setquota_total                The total number of IMAP SETQUOTAs
metric counter cyrus_imap_sort_total                    The total number of IMAP SORTs
metric counter cyrus_imap_status_total                  The total number of IMAP STATUSs
metric counter cyrus_imap_scan_total                    The total number of IMAP SCANs
metric counter cyrus_imap_thread_total                  The total number of IMAP THREADs
metric counter cyrus_imap_unauthenticate_total          The total number of IMAP UNAUTHENTICATEs
metric counter cyrus_imap_unsubscribe_total             The total number of IMAP UNSUBSCRIBEs
metric counter cyrus_imap_unselect_total                The total number of IMAP UNSELECTs
metric counter cyrus_imap_xbackup_total                 The total number of IMAP XBACKUPs

metric counter cyrus_lmtp_connections_total             The total number of LMTP connections
metric gauge   cyrus_lmtp_active_connections            The number of active LMTP connections
metric gauge   cyrus_lmtp_ready_listeners               The number of currently ready LMTP listeners
metric counter cyrus_lmtp_shutdown_total                The number of LMTP process shutdowns
    label cyrus_lmtp_shutdown_total status ok error
metric counter cyrus_lmtp_authenticate_total            The total number of IMAP AUTHENTICATEs
    label cyrus_lmtp_authenticate_total result yes no
metric counter cyrus_lmtp_received_messages_total       The number of messages received
metric counter cyrus_lmtp_received_bytes_total          The number of received bytes
metric counter cyrus_lmtp_received_recipients_total     The number of received recipients
metric counter cyrus_lmtp_transmitted_messages_total    The number of messages transmitted
metric counter cyrus_lmtp_transmitted_bytes_total       The number of bytes transmitted
metric counter cyrus_lmtp_sieve_redirect_total          The number of sieve REDIRECTs
metric counter cyrus_lmtp_sieve_discard_total           The number of sieve DISCARDs
metric counter cyrus_lmtp_sieve_reject_total            The number of sieve REJECTs
metric counter cyrus_lmtp_sieve_fileinto_total          The number of sieve FILEINTOs
metric counter cyrus_lmtp_sieve_snooze_total            The number of sieve SNOOZEs
metric counter cyrus_lmtp_sieve_keep_total              The number of sieve KEEPs
metric counter cyrus_lmtp_sieve_notify_total            The number of sieve NOTIFYs
metric counter cyrus_lmtp_sieve_imip_total              The number of sieve IMIPs
metric counter cyrus_lmtp_sieve_autorespond_total       The number of sieve AUTORESPONDs considered
metric counter cyrus_lmtp_sieve_autorespond_sent_total  The number of sieve AUTORESPONDs sent

metric counter cyrus_http_connections_total       The total number of HTTP connections
metric gauge   cyrus_http_active_connections      The number of active HTTP connections
metric gauge   cyrus_http_ready_listeners         The number of currently ready HTTP listeners
metric counter cyrus_http_shutdown_total          The number of HTTP process shutdowns
    label cyrus_http_shutdown_total status ok error
metric counter cyrus_http_acl_total               The total number of HTTP ACLs
    label cyrus_http_acl_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_bind_total              The total number of HTTP BINDs
    label cyrus_http_bind_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_connect_total           The total number of HTTP CONNECTvs
    label cyrus_http_connect_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_copy_total              The total number of HTTP COPYs
    label cyrus_http_copy_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_delete_total            The total number of HTTP DELETEs
    label cyrus_http_delete_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_get_total               The total number of HTTP GETs
    label cyrus_http_get_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_head_total              The total number of HTTP HEADs
    label cyrus_http_head_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_lock_total              The total number of HTTP LOCKs
    label cyrus_http_lock_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_mkcalendar_total        The total number of HTTP MKCALENDARs
    label cyrus_http_mkcalendar_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_mkcol_total             The total number of HTTP MKCOLs
    label cyrus_http_mkcol_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_move_total              The total number of HTTP MOVEs
    label cyrus_http_move_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_options_total           The total number of HTTP OPTIONSs
    label cyrus_http_options_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_patch_total             The total number of HTTP PATCHs
    label cyrus_http_patch_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_post_total              The total number of HTTP POSTs
    label cyrus_http_post_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_propfind_total          The total number of HTTP PROPFINDs
    label cyrus_http_propfind_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_proppatch_total         The total number of HTTP PROPPATCHs
    label cyrus_http_proppatch_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_put_total               The total number of HTTP PUTs
    label cyrus_http_put_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_report_total            The total number of HTTP REPORTs
    label cyrus_http_report_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_search_total            The total number of HTTP SEARCH
    label cyrus_http_search_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_trace_total             The total number of HTTP TRACEs
    label cyrus_http_trace_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_unbind_total            The total number of HTTP UNBINDs
    label cyrus_http_unbind_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
metric counter cyrus_http_unlock_total            The total number of HTTP UNLOCKs
    label cyrus_http_unlock_total namespace default admin applepush calendar freebusy addressbook principal notify dblookup ischedule domainkeys jmap prometheus rss tzdist drive cgi
