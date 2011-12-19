PACKAGE = "Release_Notes"

all: clean clean_ids
	@publican build --langs=en-US --formats=html,html-single,pdf --publish --embedtoc
	@publican install_book --site_config=../site.cfg --lang en-US
	@mkdir -p tmp/en-US/txt/
	@w3m -dump tmp/en-US/html-single/index.html > tmp/en-US/txt/$(PACKAGE).txt

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
