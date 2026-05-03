.. _imap-admin-monitoring:

==========
Monitoring
==========

Cyrus IMAP supports monitoring using Prometheus_.

To use this functionality, Cyrus IMAP must have been built with the
``--enable-http`` configure option enabled.

.. _imap-admin-monitoring-setup:

Setup
=====

    * Set :imapdconf:`prometheus_enabled` option to "yes"
    * Add the `prometheus` module to your :imapdconf:`httpmodules`
    * Set the :imapdconf:`prometheus_need_auth`,
      :imapdconf:`prometheus_service_update_freq`,
      :imapdconf:`prometheus_master_update_freq`,
      :imapdconf:`prometheus_usage_update_freq`, and
      :imapdconf:`prometheus_stats_dir` settings to taste
    * Add a job to run :cyrusman:`promstatsd(8)` to the DAEMON section of
      :cyrusman:`cyrus.conf(5)` (the actual daemon process)
    * Add a job to run ``promstatsd -c`` to the START section of :cyrusman:`cyrus.conf(5)`
      (this cleans up the stats files from the previous run)
    * Configure your Prometheus server to scrape http://yourserver.example.com/metrics

Configuration options
=====================

    * :imapdconf:`prometheus_enabled`
    * :imapdconf:`prometheus_need_auth`
    * :imapdconf:`prometheus_service_update_freq`
    * :imapdconf:`prometheus_master_update_freq`
    * :imapdconf:`prometheus_usage_update_freq`
    * :imapdconf:`prometheus_stats_dir`

.. _imap-admin-monitoring-end:

Back to :ref:`imap-admin`

.. _Prometheus: https://prometheus.io
