PACKAGE = "Release_Notes"

all: clean clean_ids
	@publican build --langs=en-US --formats=html,html-single,pdf
	@rsync -aHvz tmp/en-US/{html,html-single,pdf} www.cyrusimap.org:./public_html/cyrus-imapd-2.4-docs/$(PACKAGE)/

clean:
	@publican clean

clean_ids:
	@cp -a ../Common_Content/en-US/*.xml en-US/.
	@publican clean_ids
	@sed -i -r \
		-e 's/\t/    /g' \
		-e 's/((\s{4})+)\s*/\1/g' \
		-e 's/\s*$$//g' \
		`find en-US/ -type f -name "*.xml"`
