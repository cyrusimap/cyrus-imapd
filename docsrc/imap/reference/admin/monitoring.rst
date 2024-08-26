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

    * Set the `prometheus_enabled` setting in :cyrusman:`imapd.conf(5)` to "yes"
    * Add the `prometheus` module to your `httpmodules` in :cyrusman:`imapd.conf(5)`
    * Set the `prometheus_need_auth`, `prometheus_service_update_freq`,
      `prometheus_master_update_freq`, `prometheus_usage_update_freq`, and
      `prometheus_stats_dir` settings in :cyrusman:`imapd.conf(5)` to taste
    * Add a job to run :cyrusman:`promstatsd(8)` to the DAEMON section of
      :cyrusman:`cyrus.conf(5)` (the actual daemon process)
    * Add a job to run ``promstatsd -c`` to the START section of :cyrusman:`cyrus.conf(5)`
      (this cleans up the stats files from the previous run)
    * Configure your Prometheus server to scrape http://yourserver.example.com/metrics

Configuration options
=====================

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob prometheus_enabled
        :end-before: endblob prometheus_enabled

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob prometheus_need_auth
        :end-before: endblob prometheus_need_auth

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob prometheus_service_update_freq
        :end-before: endblob prometheus_service_update_freq

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob prometheus_master_update_freq
        :end-before: endblob prometheus_master_update_freq

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob prometheus_usage_update_freq
        :end-before: endblob prometheus_usage_update_freq

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob prometheus_stats_dir
        :end-before: endblob prometheus_stats_dir

.. _imap-admin-monitoring-end:

Back to :ref:`imap-admin`

.. _Prometheus: https://prometheus.io
