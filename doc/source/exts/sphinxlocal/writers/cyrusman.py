"""
    sphinxlocal.writers.cyrusman
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Turn :cyrusman: links into manpage references to the cyrus imap doc tree

    :version: 0.1
    :author: Nicola Nye <nicolan@fastmail.com>

    :copyright: Copyright 2007-2015 by the Sphinx team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

from docutils import nodes, utils
from docutils.parsers.rst.roles import set_classes
from string import Template
import re

def make_link_node(rawtext, app, name, manpage_num, options):
    """Create a link to a man page.
    """
    sections = ['general','system','library','special','configs','games','misc','commands']
    manpage_section = sections[int(manpage_num)-1]
    urlname = None
    if manpage_num == '5':
        urlname= name + ".conf"
    else:
        urlname = name
    ref = None
    ref = app.config.cyrus_man_url_regex
    if not ref:
        ref = "http://docs.cyrus.foundation/imap/admin/%s/%s.html" % (manpage_section, urlname)
    else:
        s = Template(ref)     
        ref = s.substitute(num=manpage_section, topic=urlname)
    set_classes(options)
    node = nodes.reference(rawtext, "%s(%s)" % (name, manpage_num), refuri=ref,
                           **options)
    return node
    

def man_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
    """Link to an online man page issue.
    """
    app = inliner.document.settings.env.app
    p = re.compile("([a-zA-Z0-9_\.-_]+)\((\d)\)")
    m = p.match(text)

    manpage_num = m.group(2)
    name = m.group(1)
    node = make_link_node(rawtext, app, name, manpage_num, options)
    return [node], []

def setup(app):
    app.info('Initializing cyrusman plugin')
    app.add_role('cyrusman', man_role)
    app.add_config_value('cyrus_man_url_regex', None, 'env')
    return
