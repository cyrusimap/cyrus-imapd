# -*- coding: utf-8 -*-
"""
    sphinxlocal.builders.insertdatestamp
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Inserts a git datestamp into the context as 'gitstamp',
    to make it available for template use.

    Adds itself as a page context handler: gets invoked after source
    is read but before html is output.

    :version: 0.1
    :author: Nicola Nye <nicolan@fastmail.com>

    :copyright: Copyright 2007-2016 by the Cyrus team,
    :license: BSD, see LICENSE for details.
"""

import git, datetime

# Gets the datestamp of the latest commit on the given file
# Converts the datestamp into something more readable
# Skips files not known to git or those whose datestamp we can't parse.
# Expected git datestamp format: 2017-06-07 11:57:38 +1000
# Output to June 7, 2017
def page_context_handler(app, pagename, templatename, context, doctree):
        g = git.Git('.')
        try:
            updated = g.log('--pretty=format:%ai','-n 1',"%s.rst" % pagename)
            context['gitstamp'] = datetime.datetime.strptime(updated, "%Y-%m-%d %H:%M:%S %z").strftime("%b %d %Y")
        except git.exc.GitCommandError:
            # File not in git. No point trying to add in a datestamp
            pass;
        except ValueError:
            # Datestamp is weird.
            pass;


#
#     git log --format=%ai -n 1
#
# The pagename argument is the canonical name of the page being rendered, that is, without .html suffix and using slashes as path separators. The templatename is the name of the template to render, this will be 'page.html' for all pages from reST documents.
# The context argument is a dictionary of values that are given to the template engine to render the page and can be modified to include custom values. Keys must be strings.
# The doctree argument will be a doctree when the page is created from a reST documents; it will be None when the page is created from an HTML template alone.
# You can return a string from the handler, it will then replace 'page.html' as the HTML template for this page.

def setup(app):
    app.connect('html-page-context', page_context_handler)
