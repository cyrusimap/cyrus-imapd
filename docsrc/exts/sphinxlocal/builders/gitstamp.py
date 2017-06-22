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

    :copyright: Copyright 2007-2016 by the Cyrus team,
    :license: BSD, see LICENSE for details.
"""
from sphinx import errors

import datetime

# Gets the datestamp of the latest commit on the given file
# Converts the datestamp into something more readable
# Skips files not known to git or those whose datestamp we can't parse.
# Expected git datestamp format: 2017-06-07 11:57:38 +1000
# Output to June 7, 2017
def page_context_handler(app, pagename, templatename, context, doctree):
        global g
        if g is None:
            # We have already errored about this
            pass
        try:
            updated = g.log('--pretty=format:%ai','-n 1',"%s.rst" % pagename)
            context['gitstamp'] = datetime.datetime.strptime(updated, "%Y-%m-%d %H:%M:%S %z").strftime(app.config.gitstamp_fmt)
        except (git.exc.GitCommandError, ValueError):
            # File not in git. No point trying to add in a datestamp, or
            # Datestamp can't be parsed.
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
