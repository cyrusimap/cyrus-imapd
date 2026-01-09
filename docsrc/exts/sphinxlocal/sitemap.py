"""
sphinxlocal.sitemap
~~~~~~~~~~~~~~~~~~~
Generate google sitemap if doing an html output build.
Placed in build/html/sitemap.xml

Use sitemap_website to specify the webroot where the files will be
served.

:version: 0.1
:author: Nicola Nye <nicola@fastmailteam.com>

:copyright: Copyright Carnegie Mellon University.
:license: BSD-3-Clause-CMU, see COPYING for details.
"""

import os
import xml.etree.ElementTree
from sphinx import errors

namespace = "http://www.sitemaps.org/schemas/sitemap/0.9"

def generate_sitemap(app, exception):
    if exception:
        return

    urls = []
    website = app.config.sitemap_website
    if website is None:
        raise errors.ExtensionError("Cannot generate sitemap. Set 'sitemap_website' in conf.py with website hostname")

    env = app.builder.env
    for page in sorted(env.found_docs):
        for site in website:
            url = {}
            url["loc"] = "{}{}.html".format(site, page)

            # If we can deduce last modified time from gitstamp,
            # then we can publish this here.
            # url["lastmod"] = ...

            urls.append(url)

    urlset = xml.etree.ElementTree.Element("urlset", {"xmlns": namespace})
    for url in urls:
        url_element = xml.etree.ElementTree.SubElement(urlset, "url")

        loc = xml.etree.ElementTree.SubElement(url_element, "loc")
        loc.text = url["loc"]

        if "lastmod" in url:
            lastmod = xml.etree.ElementTree.SubElement(url_element, "lastmod")
            lastmod.text = url["lastmod"]


    tree = xml.etree.ElementTree.ElementTree(urlset)
    tree.write(os.path.join(app.outdir, "sitemap.xml"), "UTF-8", True)

# Only add the sitemap generator if we're generating html
def what_build_am_i(app):
    if (app.builder.format != 'html'):
        return;

    app.connect("build-finished", generate_sitemap)

# We can't immediately add the generator: we need to wait until we
# know what the build output format is. Don't want to output for anything
# other than html output
def setup(app):
    app.add_config_value("sitemap_website", None, '')
    app.connect('builder-inited', what_build_am_i)
