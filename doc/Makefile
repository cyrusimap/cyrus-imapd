SUBDIRS = \
	Administrator_Guide \
	Deployment_Guide \
	Installation_Guide \
	Release_Notes

all:
	@for dir in $(SUBDIRS); do \
		cp -a Common_Content/en-US/*.xml $$dir/en-US/.; \
		make -C $$dir; \
	done

upload:
	@for dir in $(SUBDIRS); do \
		cp -a Common_Content/en-US/*.xml $$dir/en-US/.; \
		make -C $$dir upload; \
	done
