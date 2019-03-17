# -*- coding: utf-8 -*-
"""
    sphinxlocal.writers.manpage
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    A replacement for the manpage builder which come bundled with Sphinx.

    :version: 0.1
    :author: Nic Bernstein <nic@onlight.com>

    :copyright: Copyright 2007-2016 by the Sphinx team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

import docutils
from docutils import nodes
from sphinx.writers.manpage import (
    ManualPageWriter,
    ManualPageTranslator as BaseTranslator
)

docutils_version_info = tuple(map(int, docutils.__version__.split('.')))
if docutils_version_info < (0, 11):
  from sphinx.writers.manpage import MACRO_DEF


from sphinx import addnodes
from sphinx.locale import admonitionlabels, _
from time import strftime

class CyrusManualPageWriter(ManualPageWriter):

    #settings_spec = (u'No options defined.', u'', ())
    #settings_defaults = {}

    def __init__(self, builder):
        ManualPageWriter.__init__(self, builder)
        self.builder = builder

    def translate(self):
        visitor = CyrusManualPageTranslator(self.builder, self.document)
        self.visitor = visitor
        self.document.walkabout(visitor)
        self.output = visitor.astext()


class CyrusManualPageTranslator(BaseTranslator):
    """
    Custom translator.
    """

    def __init__(self, builder, *args, **kwds):
        BaseTranslator.__init__(self, builder, *args, **kwds)
        self.builder = builder

        self.in_productionlist = 0

        # first title is the manpage title
        self.section_level = -1

        # docinfo set by man_pages config value
        self._docinfo['title'] = self.document.settings.title
        self._docinfo['subtitle'] = self.document.settings.subtitle
        if self.document.settings.authors:
            # don't set it if no author given
            self._docinfo['author'] = self.document.settings.authors
        self._docinfo['manual_section'] = self.document.settings.section

        # docinfo set by other config values
        self._docinfo['title_upper'] = self._docinfo['title'].upper()
        self._docinfo['date'] = builder.config.today or strftime(builder.config.today_fmt or _('%B %d, %Y'))
        self._docinfo['copyright'] = builder.config.copyright
        self._docinfo['version'] = builder.config.version
        self._docinfo['manual_group'] = builder.config.project

        # In docutils < 0.11 self.append_header() was never called
        if docutils_version_info < (0, 11):
          self.body.append(MACRO_DEF)

        # overwritten -- don't wrap literal_block with font calls
        self.defs['literal_block'] = ('.sp\n.nf\n', '\n.fi\n')


    # overwritten -- don't assume indentation
    def visit_literal_block(self, node):
        self.body.append(self.defs['literal_block'][0])
        self._in_literal = True


    def depart_literal_block(self, node):
        self._in_literal = False
        self.body.append(self.defs['literal_block'][1])
