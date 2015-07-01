# -*- coding: utf-8 -*-
"""
    sphinxlocal.writers.manpage
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    A replacement for the manpage builder which come bundled with Sphinx.

    :version: 0.1
    :author: Nic Bernstein <nic@onlight.com>

    :copyright: Copyright 2007-2014 by the Sphinx team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

from docutils import nodes
try:
    from sphinx.writers.manpage import MACRO_DEF, ManualPageWriter, \
         ManualPageTranslator as BaseTranslator
    has_manpage_writer = True
except ImportError:
    # define the classes in any case, sphinx.application needs it
    Writer = BaseTranslator = object
    has_manpage_writer = False

from sphinx import addnodes
from sphinx.locale import admonitionlabels, _
from sphinx.util.osutil import ustrftime
##
# NB: The following was removed for compatibility with sphinx
# version 1.1.3.
#
#from sphinx.util.compat import docutils_version

LITERAL_BLOCK_INDENT = 3.5

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
        if builder.config.today:
            self._docinfo['date'] = builder.config.today
        else:
            self._docinfo['date'] = ustrftime(builder.config.today_fmt
                                              or _('%B %d, %Y'))
        self._docinfo['copyright'] = builder.config.copyright
        self._docinfo['version'] = builder.config.version
        self._docinfo['manual_group'] = builder.config.project

        # since self.append_header() is never called, need to do this here
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

    ##
    # Everything below this comment has been back-ported from newer
    # versions of docutils and sphinx.  The manpage writers in the old
    # versions of these packages, as installed on Wheezy, are not
    # capable of writing proper man pages as they sit.  Everything
    # from this comment on down should be removed for newer versions
    # of these packages, such as docutils >= 0.11 or sphinx >= 1.2
    
    # overwritten -- fix bugs in docutils-0.8.1 definitions (these fixes
    # are all cribbed from docutils-0.11.3)
    def visit_Text(self, node):
        text = node.astext()
        text = text.replace('\\','\\e')
        replace_pairs = [
            (u'-', ur'\-'),
            (u'\'', ur'\(aq'),
            (u'´', ur'\''),
            (u'`', ur'\(ga'),
            ]
        for (in_char, out_markup) in replace_pairs:
            text = text.replace(in_char, out_markup)
        # unicode
        text = self.deunicode(text)
        # prevent interpretation of "." at line start
        if text.startswith('.'):
            text = '\\&' + text
        if self._in_literal:
            text = text.replace('\n.', '\n\\&.')
        self.body.append(text)

    def ensure_eol(self):
        """Ensure the last line in body is terminated by new line."""
        if len(self.body) > 0 and self.body[-1][-1] != '\n':
            self.body.append('\n')

    def astext(self):
        """Return the final formatted document as a string."""
        if not self.header_written:
            # ensure we get a ".TH" as viewers require it.
            self.append_header()
        # filter body
        for i in xrange(len(self.body)-1, 0, -1):
            # remove superfluous vertical gaps.
            if self.body[i] == '.sp\n':
                if self.body[i - 1][:4] in ('.BI ','.IP '):
                    self.body[i] = '.\n'
                elif (self.body[i - 1][:3] == '.B ' and
                    self.body[i - 2][:4] == '.TP\n'):
                    self.body[i] = '.\n'
                elif (self.body[i - 1] == '\n' and
                    not self.possibly_a_roff_command.match(self.body[i - 2]) and
                    (self.body[i - 3][:7] == '.TP\n.B '
                        or self.body[i - 3][:4] == '\n.B ')
                     ):
                    self.body[i] = '.\n'
        return ''.join(self.head + self.body + self.foot)

    def append_header(self):
        """append header with .TH and .SH NAME"""
        # NOTE before everything
        # .TH title_upper section date source manual
        if self.header_written:
            return
        self.head.append(self.header())
        self.head.append(MACRO_DEF)
        self.header_written = 1

    def visit_admonition(self, node, name=None):
        #
        # Make admonitions a simple block quote
        # with a strong heading
        #
        # Using .IP/.RE doesn't preserve indentation
        # when admonitions contain bullets, literal,
        # and/or block quotes.
        #
        if name:
            # .. admonition:: has no name
            self.body.append('.sp\n')
            name = '%s%s:%s\n' % (
                self.defs['strong'][0],
                self.language.labels.get(name, name).upper(),
                self.defs['strong'][1],
                )        
            self.body.append(name)
        self.visit_block_quote(node)

    def depart_admonition(self, node):
        self.depart_block_quote(node)

    def visit_document(self, node):
        # no blank line between comment and header.
        self.head.append(self.comment(self.document_start).rstrip()+'\n')
        # writing header is postboned
        self.header_written = 0

    def visit_option(self, node):
        # each form of the option will be presented separately
        if self.context[-1] > 0:
            self.body.append('\\fP,\\fB ')
        if self.context[-3] == '.BI':
            self.body.append('\\')
        self.body.append(' ')


    # overwritten -- fix bugs in sphinx-1.1.3 definitions (these fixes
    # are all cribbed from sphinx-1.2.3)
    def visit_seealso(self, node):
        self.visit_admonition(node, 'seealso')

    def visit_productionlist(self, node):
        self.ensure_eol()
        names = []
        self.in_productionlist += 1
        self.body.append('.sp\n.nf\n')
        for production in node:
            names.append(production['tokenname'])
        maxlen = max(len(name) for name in names)
        lastname = None
        for production in node:
            if production['tokenname']:
                lastname = production['tokenname'].ljust(maxlen)
                self.body.append(self.defs['strong'][0])
                self.body.append(self.deunicode(lastname))
                self.body.append(self.defs['strong'][1])
                self.body.append(' ::= ')
            elif lastname is not None:
                self.body.append('%s     ' % (' '*len(lastname)))
            production.walkabout(self)
            self.body.append('\n')
        self.body.append('\n.fi\n')
        self.in_productionlist -= 1
        raise nodes.SkipNode

    def visit_reference(self, node):
        self.body.append(self.defs['reference'][0])
        self.visit_Text(node)  # avoid repeating escaping code... fine since
                               # visit_Text calls astext() and only works
                               # on that afterwards
        self.body.append(self.defs['reference'][1])

        uri = node.get('refuri', '')
        if uri.startswith('mailto:') or uri.startswith('http:') or \
                 uri.startswith('https:') or uri.startswith('ftp:'):
            # if configured, put the URL after the link
            if self.builder.config.man_show_urls and \
                   node.astext() != uri:
                if uri.startswith('mailto:'):
                    uri = uri[7:]
                self.body.extend([
                    ' <',
                    self.defs['strong'][0], uri, self.defs['strong'][1],
                    '>'])
        raise nodes.SkipNode

    def visit_literal_strong(self, node):
        return self.visit_strong(node)

    def depart_literal_strong(self, node):
        return self.depart_strong(node)
