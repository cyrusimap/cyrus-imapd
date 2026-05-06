# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

import docutils;

def setup(app):
    app.add_crossref_type('imapdconf',
                          'imapdconf',
                          'single: %s',
                          docutils.nodes.literal)
    return
