SUBDIRS = \
	Administrator_Guide \
	Deployment_Guide \
	Installation_Guide

all:
	@for dir in $(SUBDIRS); do \
		cd $$dir; \
		publican build --langs=en-US --formats=html,html-single,pdf; \
		rsync -aHvz tmp/en-US/{html,html-single,pdf} www.cyrusimap.org:./public_html/cyrus-imapd-2.4-docs/$$dir/; \
		cd ..; \
	done
