"""
    sphinxlocal.roles.cyrusman
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Turn :cyrusman: links into manpage references to the cyrus imap doc tree

    Config: use 'cyrus_man_url_regex' to set the location for generated links. Defaults to http://www.cyrusimap.org/imap/admin/%s/%s.html

    If :cyrusman: references are missing the section number, it die with an error.

    :version: 0.1
    :author: Nicola Nye <nicolan@fastmail.com>

    :copyright: Copyright 2007-2016 by the Sphinx team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

from sphinx.errors import SphinxError
from docutils import nodes, utils
from docutils.parsers.rst.roles import set_classes
from string import Template
import re


def make_link_node(rawtext, app, name, manpage_num, options):
    """Create a link to a man page.
    """
#   These section names map to directory names. ie: section 8 will generate a url to 'systemcommands'
    sections = ['usercommands','system','libraries','special','configs','games','misc','systemcommands']
    manpage_section = sections[int(manpage_num)-1]
    ref = None
    ref = app.config.cyrus_man_url_regex
    if not ref:
        ref = "http://www.cyrusimap.org/stable/imap/admin/%s/%s.html" % (manpage_section, name)
    else:
        s = Template(ref)
        ref = s.substitute(num=manpage_section, topic=name)
    set_classes(options)
    node = nodes.reference(rawtext, "%s(%s)" % (name, manpage_num), refuri=ref,
                           **options)
    return node


def man_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
    """Link to an online man page issue.
    """
    env = inliner.document.settings.env
    app = env.app
#   name: alphanumeric including dots, dashes and underscores.
#   section: Is in brackets, and is a single digit number. There may also be some non-numeric stuff after the number that we don't care about.
    p = re.compile("(?P<name>[a-zA-Z0-9_\.\-_]+)(\((?P<section>\d)(?:[^\d])*\))?")
    m = p.match(text)
    if (m.group('section')):
        manpage_num = m.group('section')
    else:
        raise CyrusManExtension(env.docname+': '+str(lineno)+": Missing man page section for \'"+text+"\'.")
    name = m.group('name')
    node = make_link_node(rawtext, app, name, manpage_num, options)
    return [node], []

def setup(app):
    app.info('Initializing cyrusman plugin')
    app.add_role('cyrusman', man_role)
    app.add_config_value('cyrus_man_url_regex', None, 'env')
    return

class CyrusManExtension(SphinxError):
        category = ':cyrusman: error'
