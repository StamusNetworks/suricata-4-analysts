# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------

project = 'Network Threat Hunting with Suricata'
copyright = '2021-2022, Stamus Networks'
author = 'Eric Leblond and Peter Manev'

# The full version, including alpha/beta/rc tags
release = '0.2'


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'alabaster'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

numfig = True

latex_show_urls = 'footnote'

latex_elements = {
    'pointsize': '10pt',
    'preamble': r'''
\usepackage{stamus}
''',
    'maketitle': r'''
\makeatletter
\begin{titlepage}
\AddToShipoutPictureBG*{\BackgroundPic}
\py@HeaderFamily
\vspace*{2.5cm}
\hspace*{-1.1cm}
\begin{minipage}{12cm}
\textcolor{yellow}{
\textbf{
\begin{spacing}{1.2}
\fontsize{45}{55}\selectfont \@title
\end{spacing}
}
}

\vspace{0.4cm}
\textcolor{white}
{
\LARGE{by \@author}
}
\end{minipage}
\par
\vspace*{\fill}
\hspace*{-1.1cm}
\textcolor{white}{
\py@release \releaseinfo
}
\end{titlepage}
\AddToShipoutPictureBG{\transparent{0.5}\includegraphics[width=\paperwidth,height=12cm]{stamus-background.jpg}}
\makeatother
'''
}

latex_additional_files = ["stamus.sty", "img/stamus-logo.png", "img/stamus-background.jpg", "img/stamus-title.jpg"]

latex_logo = "img/stamus-logo.png"
