# Prometheus metric definitions file
#
# metric <type> <name> <description>
#         type is one of "counter" or "gauge"
#                name must be [a-z0-9_] only
#                       description is free text until EOL but don't be silly
#
# '#' begins a comment
#
metric counter imap_connections_total  The total number of IMAP connections
metric gauge   imap_active_connections The number of currently active IMAP connections
metric counter imap_authenticate_count The total number of IMAP authentications
metric counter imap_append_count       The total number of IMAP APPENDs
metric counter imap_capability_count   The total number of IMAP CAPABILITYs
metric counter imap_compress_count     The total number of IMAP COMPRESSs
metric counter imap_check_count        The total number of IMAP checks
metric counter imap_copy_count         The total number of IMAP COPYs
metric counter imap_create_count       The total number of IMAP CREATEs
metric counter imap_close_count        The total number of IMAP CLOSEs
metric counter imap_delete_count       The total number of IMAP DELETEs
metric counter imap_deleteacl_count    The total number of IMAP DELETEACLs
metric counter imap_dump_count         The total number of IMAP DUMPs
metric counter imap_expunge_count      The total number of IMAP EXPUNGEs
metric counter imap_examine_count      The total number of IMAP EXAMINEs
metric counter imap_fetch_count        The total number of IMAP FETCHs
metric counter imap_getacl_count       The total number of IMAP GETACLs
