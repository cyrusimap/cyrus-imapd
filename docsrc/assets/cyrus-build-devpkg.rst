As well as all of the things needed for building Cyrus itself, we'll
also install some packages needed to support Cassandane -- the
automated test facility.

.. code-block:: bash

    sudo apt-get install -y autoconf automake autotools-dev bash-completion bison build-essential comerr-dev \
        debhelper flex g++ git gperf groff heimdal-dev libbsd-resource-perl libclone-perl libconfig-inifiles-perl \
        libcunit1-dev libdatetime-perl libdb-dev libdigest-sha-perl libencode-imaputf7-perl libfile-chdir-perl \
        libglib2.0-dev libical-dev libio-socket-inet6-perl libio-stringy-perl libjansson-dev libldap2-dev \
        libmysqlclient-dev libnet-server-perl libnews-nntpclient-perl libpam0g-dev libpcre3-dev libsasl2-dev \
        libsnmp-dev libsqlite3-dev libssl-dev libtest-unit-perl libtool libunix-syslog-perl liburi-perl \
        libxapian-dev libxml-generator-perl libxml-xpath-perl libxml2-dev libwrap0-dev libzephyr-dev lsb-base \
        net-tools perl php5-cli php5-curl pkg-config po-debconf tcl-dev \
        transfig uuid-dev vim wamerican wget xutils-dev zlib1g-dev sasl2-bin rsyslog sudo acl telnet
