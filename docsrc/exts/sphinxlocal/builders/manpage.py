# -*- coding: utf-8 -*-
"""
    sphinxlocal.builders.manpage
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    A replacement for the manpage builder which come bundled with Sphinx.

    :version: 0.1
    :author: Nic Bernstein <nic@onlight.com>

    :copyright: Copyright 2007-2016 by the Sphinx team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

from os import path

from six import string_types
from docutils.io import FileOutput
from docutils.frontend import OptionParser

from sphinx import addnodes
from sphinx.errors import SphinxError
from sphinx.builders import Builder
from sphinx.util.nodes import inline_all_toctrees
from sphinx.util.console import bold, darkgreen
from sphinx.writers.manpage import ManualPageWriter
from sphinx.builders.manpage import ManualPageBuilder

##
# Import our customized version of the stock Writer, which has the
# Translater in it.
from sphinxlocal.writers.manpage import CyrusManualPageWriter

try:
    from sphinx.util import logging
    logger = logging.getLogger(__name__)
except:
    logger = None

class CyrusManualPageBuilder(ManualPageBuilder):
    """
    Builds groff output in manual page format.
    """
    name = 'cyrman'
    format = 'man'
    supported_image_types = []

    #settings_spec = (u'No options defined.', u'', ())
    #settings_defaults = {}

    def init(self):
        global logger
        if logger is None:
            logger = self
        if not self.config.man_pages:
            logger.warn('no "man_pages" config value found; no manual pages '
                      'will be written')

    def write(self, *ignored):
        # overwritten -- use our own version of the Writer
        docwriter = CyrusManualPageWriter(self)
        docsettings = OptionParser(
            defaults=self.env.settings,
            components=(docwriter,),
            read_config_files=True).get_default_values()

        logger.info(bold('writing... '), nonl=True)

        for info in self.config.man_pages:
            docname, name, description, authors, section = info
            if isinstance(authors, string_types):
                if authors:
                    authors = [authors]
                else:
                    authors = []

            targetname = '%s.%s' % (name, section)
            logger.info(darkgreen(targetname) + ' { ', nonl=True)
            destination = FileOutput(
                destination_path=path.join(self.outdir, targetname),
                encoding='utf-8')

            tree = self.env.get_doctree(docname)
            docnames = set()
            largetree = inline_all_toctrees(self, docnames, docname, tree,
                                            darkgreen, [docname])
            logger.info('} ', nonl=True)
            self.env.resolve_references(largetree, docname, self)
            # remove pending_xref nodes
            for pendingnode in largetree.traverse(addnodes.pending_xref):
                pendingnode.replace_self(pendingnode.children)

            largetree.settings = docsettings
            largetree.settings.title = name
            largetree.settings.subtitle = description
            largetree.settings.authors = authors
            largetree.settings.section = section

            docwriter.write(largetree, destination)
        logger.info('')

def setup(app):
    app.add_builder(CyrusManualPageBuilder)
    
    return {'version': '0.1'}
