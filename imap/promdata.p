# Prometheus metric definitions file
#
# metric <type> <name> <description>
#         type is one of "counter" or "gauge"
#                name must be [a-z0-9_] only
#                       description is free text until EOL but don't be silly
#
# '#' begins a comment
#
metric counter imap_connections_total   The total number of IMAP connections
metric gauge   imap_active_connections  The number of currently active IMAP connections
metric gauge   imap_ready_listeners     The number of currently ready IMAP listeners
metric counter imap_shutdown_count      The number of IMAP process shutdowns
    label imap_shutdown_count status ok error
metric counter imap_append_count        The total number of IMAP APPENDs
metric counter imap_authenticate_count  The total number of IMAP AUTHENTICATEs
    label imap_authenticate_count result yes no
metric counter imap_capability_count    The total number of IMAP CAPABILITYs
metric counter imap_compress_count      The total number of IMAP COMPRESSs
metric counter imap_check_count         The total number of IMAP checks
metric counter imap_copy_count          The total number of IMAP COPYs
metric counter imap_create_count        The total number of IMAP CREATEs
metric counter imap_close_count         The total number of IMAP CLOSEs
metric counter imap_delete_count        The total number of IMAP DELETEs
metric counter imap_deleteacl_count     The total number of IMAP DELETEACLs
metric counter imap_dump_count          The total number of IMAP DUMPs
metric counter imap_expunge_count       The total number of IMAP EXPUNGEs
metric counter imap_examine_count       The total number of IMAP EXAMINEs
metric counter imap_fetch_count         The total number of IMAP FETCHs
metric counter imap_getacl_count        The total number of IMAP GETACLs
metric counter imap_getmetadata_count   The total number of IMAP GETMETADATAs
metric counter imap_getquota_count      The total number of IMAP GETQUOTAs
metric counter imap_getquotaroot_count  The total number of IMAP GETQUOTAROOTs
metric counter imap_genurlauth_count    The total number of IMAP GENURLAUTHs
metric counter imap_id_count            The total number of IMAP IDs
metric counter imap_idle_count          The total number of IMAP IDLEs
metric counter imap_logout_count        The total number of IMAP LOGOUTs
metric counter imap_list_count          The total number of IMAP LISTs
metric counter imap_lsub_count          The total number of IMAP LSUBs
metric counter imap_listrights_count    The total number of IMAP LISTRIGHTSs
metric counter imap_myrights_count      The total number of IMAP MYRIGHTSs
metric counter imap_mupdatepush_count   The total number of IMAP MUPDATEPUSHs
metric counter imap_starttls_count      The total number of IMAP STARTTLSs
metric counter imap_store_count         The total number of IMAP STOREs
metric counter imap_select_count        The total number of IMAP SELECTs
metric counter imap_search_count        The total number of IMAP SEARCHs
metric counter imap_subscribe_count     The total number of IMAP SUBSCRIBEs
metric counter imap_setacl_count        The total number of IMAP SETACLs
metric counter imap_setmetadata_count   The total number of IMAP SETMETADATAs
metric counter imap_setquota_count      The total number of IMAP SETQUOTAs
metric counter imap_sort_count          The total number of IMAP SORTs
metric counter imap_status_count        The total number of IMAP STATUSs
metric counter imap_scan_count          The total number of IMAP SCANs
metric counter imap_thread_count        The total number of IMAP THREADs
metric counter imap_unsubscribe_count   The total number of IMAP UNSUBSCRIBEs
metric counter imap_unselect_count      The total number of IMAP UNSELECTs
metric counter imap_xbackup_count       The total number of IMAP XBACKUPs

metric counter lmtp_connections_total       The total number of LMTP connections
metric gauge   lmtp_active_connections      The number of active LMTP connections
metric gauge   lmtp_ready_listeners         The number of currently ready LMTP listeners
metric counter lmtp_shutdown_count          The number of LMTP process shutdowns
    label lmtp_shutdown_count status ok error
metric counter lmtp_authenticate_count      The total number of IMAP AUTHENTICATEs
    label lmtp_authenticate_count result yes no
metric counter lmtp_received_messages       The number of messages received
metric counter lmtp_received_bytes          The number of received bytes
metric counter lmtp_received_recipients     The number of received recipients
metric counter lmtp_transmitted_messages    The number of messages transmitted
metric counter lmtp_transmitted_bytes       The number of bytes transmitted
metric counter lmtp_sieve_redirect_count    The number of sieve REDIRECTs
metric counter lmtp_sieve_discard_count     The number of sieve DISCARDs
metric counter lmtp_sieve_reject_count      The number of sieve REJECTs
metric counter lmtp_sieve_fileinto_count    The number of sieve FILEINTOs
metric counter lmtp_sieve_keep_count        The number of sieve KEEPs
metric counter lmtp_sieve_notify_count      The number of sieve NOTIFYs
metric counter lmtp_sieve_autorespond_total The number of sieve AUTORESPONDs considered
metric counter lmtp_sieve_autorespond_sent_count The number of sieve AUTORESPONDs sent
