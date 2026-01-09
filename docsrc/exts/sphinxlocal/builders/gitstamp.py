# -*- coding: utf-8 -*-
"""
    sphinxlocal.builders.insertdatestamp
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Inserts a git datestamp into the context as 'gitstamp',
    to make it available for template use. Only runs for builders that
    generate html. (not manpage)

    Adds itself as a page context handler: gets invoked after source
    is read but before html is output.

    :version: 0.1
    :author: Nicola Nye <nicolan@fastmail.com>

    :copyright: Copyright Carnegie Mellon University.
    :license: BSD-3-Clause-CMU, see COPYING for details.
"""
from sphinx import errors

import datetime
import os

# Gets the datestamp of the latest commit on the given file
# Converts the datestamp into something more readable
# Skips files whose datestamp we can't parse.
# Expected git datestamp format: 2017-06-07 11:57:38 +1000
# Output to June 7, 2017
# Use the DOCSRC environment variable to determine the root of the
# tree in git where the rst lives. Used if you are invoking this extension
# from a makefile external to the conf.py directory
def page_context_handler(app, pagename, templatename, context, doctree):
        import git
        global g
        if g is None:
            # We have already errored about this
            pass
        fullpagename = pagename
        docsrc = ''
        try:
            docsrc = os.environ['DOCSRC'] + "/"
            if docsrc != "/":
                fullpagename = docsrc + pagename
        except KeyError:
            pass

        # Don't barf on "genindex", "search", etc
        if not os.path.isfile("%s.rst" % fullpagename):
            return

        try:
            updated = g.log('--pretty=format:%ai','-n 1',"%s.rst" % fullpagename)
            updated = updated[:10]
            if updated == "":
                # Don't datestamp generated rst's (e.g. imapd.conf.rst)
                # Ideally want to check their source - lib/imapoptions, etc, but
                # that involves getting their source/output pair into the extension.
                return
            context['gitstamp'] = datetime.datetime.strptime(updated, "%Y-%m-%d").strftime(app.config.gitstamp_fmt)
        except git.exc.GitCommandError:
            # File doesn't exist or something else went wrong.
            raise errors.ExtensionError("Can't fetch git history for %s.rst. Is DOCSRC set correctly? (DOCSRC=%s)" % (fullpagename, docsrc))
        except ValueError:
            # Datestamp can't be parsed.
            app.info("%s: Can't parse datestamp () %s ) for gitstamp, output won't have last updated time." % (pagename,updated))
            pass

# Only add the page context handler if we're generating html
def what_build_am_i(app):
    global g
    if (app.builder.format != 'html'):
        return;

    try:
        import git
    except ImportError:
        raise errors.ExtensionError("gitpython package not installed. Required to generate html. Please run: pip install gitpython")

    try:
        global g
        g = git.Git('.')
    except:
        app.info(sys.exc_info()[0])
        app.warn("gitstamp extension enabled, but no git repository found. No git datestamps will be generated.")
    else:
        app.add_config_value('gitstamp_fmt', "%b %d %Y", 'html')
        app.connect('html-page-context', page_context_handler)

# We can't immediately add a page context handler: we need to wait until we
# know what the build output format is.
def setup(app):
    app.connect('builder-inited', what_build_am_i)
