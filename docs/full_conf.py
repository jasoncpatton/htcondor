# -*- coding: utf-8 -*-
#
# Read the Docs Template documentation build configuration file, created by
# sphinx-quickstart on Tue Aug 26 14:19:49 2014.
#
# This file is execfile()d with the current directory set to its
# containing dir.
#
# Note that not all possible configuration values are present in this
# autogenerated file.
#
# All configuration values have a default; values that are commented out
# serve to show the default.

import sys
import os

import re

# -- General configuration ------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinxcontrib.mermaid',
    'sphinx.ext.graphviz',
    'sphinx.ext.autosectionlabel',
    'sphinx.ext.intersphinx',
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx_autodoc_typehints',
    'nbsphinx',
    'ticket',
    'macro',
    'macro-def',
    'subcom',
    'subcom-def',
    'dag-cmd-def',
    'dag-cmd',
    'index',
    'jira',
    'classad-attribute-def',
    'tool',
    'ad-attr',
]

# nbsphinx and mermaid collide, and mermaid won't load
# unless the following is set.  Hopefully some future
# version of either will allow us to remove this hack.
# Another possible solution is to re-write the generated
# HTML to always load mermaid before nbsphinx.

nbsphinx_requirejs_path = ''

mermaid_version = '10.5.0'

autosectionlabel_prefix_document = True

# -- Options for HTML output ----------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
html_theme = 'sphinx_rtd_theme'

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
html_theme_options = {
        'display_version': False
}
 

# Add any paths that contain custom themes here, relative to this directory.
# html_theme_path = []

# The name for this set of Sphinx documents.  If None, it defaults to
# "<project> v<release> documentation".
# html_title = None

# A shorter title for the navigation bar.  Default is the same as html_title.
# html_short_title = None

# The name of an image file (relative to this directory) to place at the top
# of the sidebar.
# html_logo = None

# The name of an image file (within the static path) to use as favicon of the
# docs.  This file should be a Windows icon file (.ico) being 16x16 or 32x32
# pixels large.
# html_favicon = None

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Add any extra paths that contain custom files (such as robots.txt or
# .htaccess) here, relative to this directory. These files are copied
# directly to the root of the documentation.
# html_extra_path = []

# If not '', a 'Last updated on:' timestamp is inserted at every page bottom,
# using the given strftime format.
# html_last_updated_fmt = '%b %d, %Y'

# If true, SmartyPants will be used to convert quotes and dashes to
# typographically correct entities.
# html_use_smartypants = True

# Custom sidebar templates, maps document names to template names.
# html_sidebars = {}

# Additional templates that should be rendered to pages, maps page names to
# template names.
# html_additional_pages = {}

# If false, no module index is generated.
# html_domain_indices = True

# If false, no index is generated.
# html_use_index = True

# If true, the index is split into individual pages for each letter.
# html_split_index = False

# If true, links to the reST sources are added to the pages.
# html_show_sourcelink = True

# If true, "Created using Sphinx" is shown in the HTML footer. Default is True.
# html_show_sphinx = True

# If true, "(C) Copyright ..." is shown in the HTML footer. Default is True.
# html_show_copyright = True

# If true, an OpenSearch description file will be output, and all pages will
# contain a <link> tag referring to it.  The value of this option must be the
# base URL from which the finished HTML is served.
# html_use_opensearch = ''

# This is the file name suffix for HTML files (e.g. ".xhtml").
# html_file_suffix = None

# Output file base name for HTML help builder.
htmlhelp_basename = 'ReadtheDocsTemplatedoc'

# -- Options for LaTeX output ---------------------------------------------

latex_elements = {
    # The paper size ('letterpaper' or 'a4paper').
    # 'papersize': 'letterpaper',

    # The font size ('10pt', '11pt' or '12pt').
    # 'pointsize': '10pt',

    # Additional stuff for the LaTeX preamble.
    # 'preamble': '',
}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
    ('index', 'HTCondorManual.tex', u'HTCondor Manual',
     u'HTCondor Team', 'manual'),
]

# The name of an image file (relative to this directory) to place at the top of
# the title page.
# latex_logo = None

# For "manual" documents, if this is true, then toplevel headings are parts,
# not chapters.
# latex_use_parts = False

# If true, show page references after internal links.
# latex_show_pagerefs = False

# If true, show URL addresses after external links.
# latex_show_urls = False

# Documents to append as an appendix to all manuals.
# latex_appendices = []

# If false, no module index is generated.
# latex_domain_indices = True


# -- Options for Texinfo output -------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author,
#  dir menu entry, description, category)
texinfo_documents = [
    ('index', 'HTCondorManual', u'HTCondor Manual',
     u'HTCondor Team', 'HTCondorManual', 'HTCondor Project',
     'Miscellaneous'),
]

# Documents to append as an appendix to all manuals.
# texinfo_appendices = []

# If false, no module index is generated.
# texinfo_domain_indices = True

# How to display URL addresses: 'footnote', 'no', or 'inline'.
# texinfo_show_urls = 'footnote'

# If true, do not generate a @detailmenu in the "Top" node's menu.
# texinfo_no_detailmenu = False

# intersphinx
intersphinx_mapping = {'python': ('https://docs.python.org/3', None)}

# autodoc settings
autoclass_content = 'both'


def modify_docstring(app, what, name, obj, options, lines):
    """
    Hook function that has a chance to modify whatever comes out of autodoc.

    Parameters
    ----------
    app
        The Sphinx application object
    what
        The type of the object which the docstring belongs to
        "module", "class", "exception", "function", "method", "attribute"
    name
        The fully qualified name of the object
    obj
        The object itself
    options
        The autodoc options
    lines
        The actual lines: modify in-place!
    """
    # strip trailing C++ signature text
    for i, line in enumerate(lines):
        if 'C++ signature :' in line:
            for _ in range(len(lines) - i):
                lines.pop()
            break

    # this is Boost's dumb way of saying an object has no __init__
    for i, line in enumerate(lines):
        if line == 'Raises an exception':
            lines[i] = ''
            lines[i + 1] = ''

    # strip leading spaces
    if len(lines) > 0:
        first_indent_len = len(lines[0]) - len(lines[0].lstrip())
        for i, line in enumerate(lines):
            if len(line) > first_indent_len:
                lines[i] = line[first_indent_len:]


remove_types_from_signatures = re.compile(r' \([^)]*\)')
remove_trailing_brackets = re.compile(r']*\)$')
cleanup_commas = re.compile(r'\s*,\s*')


def modify_signature(app, what, name, obj, options, signature, return_annotation):
    """
    Hook function that has a chance to modify whatever comes out of autodoc.

    Parameters
    ----------
    app
        The Sphinx application object
    what
        The type of the object which the docstring belongs to
        "module", "class", "exception", "function", "method", "attribute"
    name
        The fully qualified name of the object
    obj
        The object itself
    options
        The autodoc options
    signature
        the function signature, of the form "(parameter_1, parameter_2)"
        or None if there was no return annotation
    return_annotation
        the function return annotation, of the form
        " -> annotation", or None if there is no return annotation

    Returns
    -------
    (signature, return_annotation)
    """
    if signature is not None:
        signature = re.sub(remove_types_from_signatures, ' ', signature)
        signature = re.sub(remove_trailing_brackets, ')', signature)
        signature = signature.replace('[,', ',')
        signature = re.sub(cleanup_commas, ', ', signature)
        signature = signature.replace('self', '')
        signature = signature.replace('( ', '(')
        signature = signature.replace('(, ', '(')

    if return_annotation == 'None :' and what == 'class':
        return_annotation = ''

    return signature, return_annotation


def setup(app):
    app.add_css_file('css/htcondor-manual.css')
    app.connect('autodoc-process-docstring', modify_docstring)
    app.connect('autodoc-process-signature', modify_signature)


# custom highlighting
# see https://pygments.org/docs/lexerdevelopment/
# and https://pygments.org/docs/tokens/

from pygments import token, lexer
from sphinx.highlighting import lexers


class CondorSubmitLexer(lexer.RegexLexer):
    name = "condor-submit"

    flags = re.MULTILINE | re.IGNORECASE

    tokens = {
        "root": [
            (r"\s+", token.Text),
            (r"^#.*?$", token.Comment.Single),
            (
                r"(if|elif)( *)(.*?)$",
                lexer.bygroups(token.Keyword, token.Text, token.Text),
            ),
            (r"(else|endif)$", token.Keyword),
            (r"^queue", token.Keyword, "queue"),
            # matches key = val
            (
                r"(\w+)( *)(=)( *)",
                lexer.bygroups(
                    token.Name.Builtin, token.Text, token.Operator, token.Text,
                ),
                "value",
            ),
            (
                r"(include\s*:)(\s*)(.*?)(\|)?$",
                lexer.bygroups(token.Keyword, token.Text, token.String, token.Keyword,),
            ),
            # examples sometimes use ... to indicate continuation
            (r"^.{3}$", token.Text),
            # catch-all for things that aren't strictly legal syntax, like <placeholders>
            (r".", token.Text),
        ],
        "value": [
            (r"\n\n", token.Text, "#pop"),
            (r"\n\s+", token.Text),
            (r"$", token.Text, "#pop"),
            (r".", token.String),
        ],
        "queue": [
            (r"\s*$", token.Text, "#pop"),
            (r"\|$", token.Keyword, "#pop"),
            (r"\(", token.Text, "inline-from"),
            (r"\s(in|matching|from)\s", token.Keyword),
            (r"\d+", token.Number.Integer),
            (r"[-\*\./\?\w]+", token.String),
            (r",", token.Text),
            (r"\s+", token.Text),
        ],
        "inline-from": [
            (r"\)", token.Text, "#pop"),
            (r"\s+", token.Text),
            (r"[-\*\./\?\w]+", token.String),
            (r",", token.Text),
        ],
    }


lexers["condor-submit"] = CondorSubmitLexer()

CLASSAD_EXPR_TOKENS = [
    (r"-|\*|/|\+|<=|>=|<|>|==|!=|=\?=|=!=|isnt|is|&&|\|\||\(|\)|{|}", token.Operator),
    (r",", token.Text),
    (r"true|false|undefined|error", token.Keyword.Constant),
    (r"\d+\.\d+", token.Number.Float),
    (r"\d+", token.Number.Integer),
    (r'"', token.String, "string"),
    (r"(my|target)", token.Name.Builtin.Pseudo),
    (r"\.", token.Operator),
    (r"(\w+)(\[)", lexer.bygroups(token.Name.Variable, token.Operator), "getter"),
    (r"\w+", token.Name.Variable),
    (r"\s+", token.Text),
]

CLASSAD_STRING_TOKENS = [
    (r'\\"', token.String),
    (r'"', token.String, "#pop"),
    (r".", token.String),
]

CLASSAD_GETTER_TOKENS = [
    (r"\]", token.Operator, "#pop"),
    (r'"', token.String, "string"),
    (r"\d+", token.Number.Integer),
    (r"\w+", token.Name.Variable),
]


class CondorClassAdLexer(lexer.RegexLexer):
    name = "condor-classad"

    flags = re.MULTILINE | re.IGNORECASE

    tokens = {
        "root": [
            (r"\s+", token.Text),
            (r"\[", token.Text, "new"),
            (
                r"(\w+)( *)(=)( *)",
                lexer.bygroups(
                    token.Name.Variable, token.Text, token.Operator, token.Text,
                ),
                "value",
            ),
            # examples sometimes use ... to indicate continuation
            (r"^\.{3}", token.Text),
        ],
        "new": [(r"\]", token.Text, "#pop"), lexer.include("root")],
        "value": [
            (r"\]", token.Text, "#pop:2"),
            (r"\n\s", token.Text),
            (r";|$", token.Text, "#pop"),
            (r"\[", token.Text, "new"),
        ] + CLASSAD_EXPR_TOKENS,
        "string": CLASSAD_STRING_TOKENS,
        "getter": CLASSAD_GETTER_TOKENS,
    }


lexers["condor-classad"] = CondorClassAdLexer()


class CondorClassAdExpressionLexer(lexer.RegexLexer):
    name = "condor-classad-expr"

    flags = re.MULTILINE | re.IGNORECASE

    tokens = {
        "root": CLASSAD_EXPR_TOKENS,
        "string": CLASSAD_STRING_TOKENS,
        "getter": CLASSAD_GETTER_TOKENS,
    }


lexers["condor-classad-expr"] = CondorClassAdExpressionLexer()

DAGMAN_COMMON = [
    (r"\s*$", token.Text, "#pop"),
    (r"\[|\]|\||<|>", token.Text),
    (r"ALL_NODES", token.Name.Variable.Magic),
    # examples sometimes use ... to indicate continuation
    (r"\.{3}", token.Text),
    (r'[\w\.\$"-=!@\\\{\}\?^]+', token.String),
    (r"\s", token.Text),
]


class CondorDAGManLexer(lexer.RegexLexer):
    name = "condor-dagman"

    flags = re.MULTILINE | re.IGNORECASE

    tokens = {
        "root": [
            (r"\s+", token.Text),
            (r"^#.*?$", token.Comment.Single),
            (r"^jobstate_log", token.Keyword, "jobstate_log"),
            (r"^job", token.Keyword, "job"),
            (r"^submit-description", token.Keyword, "submit-description"),
            (r"^parent", token.Keyword, "parent"),
            (r"^script", token.Keyword, "script"),
            (r"^pre_skip", token.Keyword, "pre_skip"),
            (r"^retry", token.Keyword, "retry"),
            (r"^abort-dag-on", token.Keyword, "abort-dag-on"),
            (r"^vars", token.Keyword, "vars"),
            (r"^priority", token.Keyword, "priority"),
            (r"^category", token.Keyword, "category"),
            (r"^maxjobs", token.Keyword, "maxjobs"),
            (r"^config", token.Keyword, "config"),
            (r"^set_job_attr", token.Keyword, "set_job_attr"),
            (r"^env", token.Keyword, "env"),
            (r"^include", token.Keyword, "include"),
            (r"^subdag", token.Keyword, "subdag"),
            (r"^splice", token.Keyword, "splice"),
            (r"^final", token.Keyword, "final"),
            (r"^provisioner", token.Keyword, "provisioner"),
            (r"^service", token.Keyword, "service"),
            (r"^dot", token.Keyword, "dot"),
            (r"^node_status_file", token.Keyword, "node_status_file"),
            (r"^save_point_file", token.Keyword, "save_point_file"),
            (r"^done", token.Keyword, "done"),
            (r"^reject", token.Keyword, "reject"),
            # examples sometimes use ... to indicate continuation
            (r"^.{3}$", token.Text),
        ],
        "job": [
            # Note: ^ is not the beginning of the substring match, but of the line.
            ( r"(\s+\S+\s+)({)", lexer.bygroups(token.Text, token.Keyword), "inline-job" ),
            ( r"\s+(\S+)\s+(\S+)", token.Text, "submit-job" ),
        ],
        "submit-description": [
            ( r"(\s+\S+\s+)({)", lexer.bygroups(token.Text, token.Keyword), "inline-job" ),
        ],
        "inline-job": [
            ( r"([^}]+)(})", lexer.bygroups(token.Text, token.Keyword), ("#pop", "submit-job") ),
        ],
        "submit-job": [
            # The option [square brackets] around the KEYWORDS are for the usage example,
            # and aren't actually legal in DAGMan.
            ( r"(\s+)(\[?DIR\]?)(\s+)(\S+)", lexer.bygroups(token.Text, token.Keyword, token.Text, token.Text) ),
            ( r"(\s+)(\[?NOOP\]?)", lexer.bygroups(token.Text, token.Keyword) ),
            ( r"(\s+)(\[?DONE\]?)", lexer.bygroups(token.Text, token.Keyword) ),
            ( r"\s*$", token.Text, "#pop:2"),
        ],
        "parent": [
            (
                r"([\s\[])(child)([\s\]])",
                lexer.bygroups(token.Text, token.Keyword, token.Text),
            ),
        ] + DAGMAN_COMMON,
        "script": [
            (
                r"([\s\[])(defer|debug|pre|post|hold)([\s\]])",
                lexer.bygroups(token.Text, token.Keyword, token.Text),
            ),
        ] + DAGMAN_COMMON,
        "pre_skip": DAGMAN_COMMON,
        "retry": [
            (
                r"([\s\[])(unless-exit)([\s\]])",
                lexer.bygroups(token.Text, token.Keyword, token.Text),
            ),
        ] + DAGMAN_COMMON,
        "abort-dag-on": [
            (
                r"([\s\[])(return)([\s\]])",
                lexer.bygroups(token.Text, token.Keyword, token.Text),
            ),
        ] + DAGMAN_COMMON,
        "vars": [
            (
                r"([\s\[])(prepend|append)([\s\]])",
                lexer.bygroups(token.Text, token.Keyword, token.Text),
            )
        ] + DAGMAN_COMMON,
        "priority": DAGMAN_COMMON,
        "category": DAGMAN_COMMON,
        "maxjobs": DAGMAN_COMMON,
        "config": DAGMAN_COMMON,
        "set_job_attr": [(r"\s=\s", token.Operator)] + DAGMAN_COMMON,
        "env": [
            (
                r"([\s\[])(GET|SET)([\s\]])",
                lexer.bygroups(token.Text, token.Keyword, token.Text)
            ),
        ] + DAGMAN_COMMON,
        "include": DAGMAN_COMMON,
        "subdag": [
            (
                r"([\s\[])(external|dir|noop|done)([\s\]])",
                lexer.bygroups(token.Text, token.Keyword, token.Text),
            ),
        ] + DAGMAN_COMMON,
        "splice": [
            (
                r"([\s\[])(dir)([\s\]])",
                lexer.bygroups(token.Text, token.Keyword, token.Text),
            ),
        ] + DAGMAN_COMMON,
        "final": [
            (
                r"([\s\[])(dir|noop)([\s\]])",
                lexer.bygroups(token.Text, token.Keyword, token.Text),
            ),
        ] + DAGMAN_COMMON,
        "provisioner": DAGMAN_COMMON,
        "service": DAGMAN_COMMON,
        "dot": [
            (
                r"([\s\[])(update|dont-update|overwrite|dont-overwrite|include)([\s\]])",
                lexer.bygroups(token.Text, token.Keyword, token.Text),
            ),
        ] + DAGMAN_COMMON,
        "node_status_file": [
            (
                r"([\s\[])(always-update)([\s\]])",
                lexer.bygroups(token.Text, token.Keyword, token.Text),
            ),
        ] + DAGMAN_COMMON,
        "save_point_file": DAGMAN_COMMON,
        "jobstate_log" : DAGMAN_COMMON,
        "done": DAGMAN_COMMON,
        "reject": DAGMAN_COMMON,
    }


lexers["condor-dagman"] = CondorDAGManLexer()

CONFIG_VALUE_SHARED = [
    # comment
    (r"^#.*?\n", token.Comment.Single),
    # booleans
    (r"\b(true|false)\b", token.Keyword.Constant),
    # security keywords
    (
        r"\b(required|optional|never|preferred|password|fs|kerberos)\b",
        token.Keyword,
    ),
    # catch-all
    (r".|\s", token.Text),
]


class CondorConfigLexer(lexer.RegexLexer):
    name = "condor-config"

    flags = re.MULTILINE | re.IGNORECASE

    tokens = {
        "root": [
            (r"\s+", token.Text),
            (r"^#.*?$", token.Comment.Single),
            (
                r"^(@?use)( +)(\w+)( *)(:)( *)([^(\s]+)(.*)$",
                lexer.bygroups(
                    token.Keyword,              # (@)use
                    token.Text,                 # spaces
                    token.Name.Variable.Magic,  # collection (feature, policy, etc.)
                    token.Text,                 # optional spaces
                    token.Text,                 # :
                    token.Text,                 # optional spaces
                    token.Name.Variable.Magic,  # config template (until '(' or newline)
                    token.Text                  # Optional remainder inline info
                ),
            ),
            (r"^@?include", token.Keyword, "include"),
            (
                r"(warning|error)( +: +)(.*)$",
                lexer.bygroups(token.Keyword, token.Keyword, token.String),
            ),
            (r"(if|elif)(.*?)$", lexer.bygroups(token.Keyword, token.Text),),
            (r"(else|endif)$", token.Keyword),
            (
                r"([\w\.]+)( *?)(@=)(\w+)$",
                lexer.bygroups(
                    token.Name.Builtin,
                    token.Text,
                    token.Operator,
                    token.Name.Namespace,
                ),
                "multi-line",
            ),
            (
                r"([\w\.]+)( *)(=)( *)",
                lexer.bygroups(
                    token.Name.Builtin, token.Text, token.Operator, token.Text,
                ),
                "value",
            ),
            (r"\s", token.Text),
        ],
        "value": [
            (r"\\\n", token.Text),
            (r"\|?$", token.Keyword, "#pop"),
        ] + CONFIG_VALUE_SHARED,
        "multi-line": [(r"@.+$", token.Name.Namespace, "#pop")] + CONFIG_VALUE_SHARED,
        "include": [
            (r"\|?$", token.Keyword, "#pop"),
            (r":", token.Keyword),
            (r"\b(ifexist|into)\b", token.Keyword),
            (r".", token.Text),
        ],
    }


lexers["condor-config"] = CondorConfigLexer()

# TODO: if I was really clever, I would re-use the classad expression fragment
# parser for condor config values... but not all config values are classad
# expressions, so that gets really hard.
