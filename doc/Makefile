SUBDIRS = \
	About_Cyrus_IMAP \
	Administrator_Guide \
	Deployment_Guide \
	Installation_Guide \
	Release_Notes \
	Sasl_Guide

all:
	@for dir in $(SUBDIRS); do \
		cp -a Common_Content/en-US/*.xml $$dir/en-US/.; \
		make -C $$dir; \
	done

upload: all
	@rsync -aHvz site/ www.cyrusimap.org:~/public_html/

dist:
	@git archive HEAD --prefix=cyrus-imapd-docs-2.5/ | gzip -c > cyrus-imapd-docs-2.5.tar.gz
