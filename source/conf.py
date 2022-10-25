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

import os

# -- Project information -----------------------------------------------------

project = 'The Security Analyst’s Guide to Suricata'
copyright = '2021-2022, Stamus Networks'
author = 'Eric Leblond and Peter Manev'

# The full version, including alpha/beta/rc tags
release = '1.0'
version  = '1.0'


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
\vspace*{4.5cm}
\hspace*{-0.9cm}
\begin{minipage}{16cm}
\textcolor{white}{
\textbf{
\raggedright
\begin{spacing}{1.1}
\fontsize{55}{65}\selectfont \@title
\end{spacing}
}
}

\vspace{-0.1cm}
\definecolor{title_yellow}{rgb}{0.984, 0.866, 0.004}
\textcolor{title_yellow}
{
\LARGE{By Eric Leblond \& Peter Manev}
}
\end{minipage}
\par
\vspace*{\fill}
\hspace*{-1.1cm}
\textcolor{white}{
\py@release \releaseinfo
}
\end{titlepage}
\vspace*{\fill}
\textit{The Security Analyst’s Guide to Suricata} \\
Copyright @ 2022 by Eric Leblond and Peter Manev \\
Published by Stamus Networks \\
450 E. 96th Street, Suite 500 \\
Indianapolis, IN 46240 \\
This work is licensed under Attribution-ShareAlike 4.0 International (CC BY-SA 4.0) license. \\
Trade hardcover: ISBN: 979-8-9871510-0-6
\makeatother
\newpage
\AddToShipoutPictureBG{\transparent{0.5}\includegraphics[width=\paperwidth,height=12cm]{stamus-background.jpg}}
''',
    'printindex': r'''
\renewcommand{\indexname}{Index}
\printindex
\cleartoleftpage
\pagestyle{empty}
\newgeometry{bottom=0.8cm}
\vspace*{\fill}
\ClearShipoutPictureBG
\AddToShipoutPictureBG{\BackCoverPic}
\sffamily
\color{white}
\hspace{-2.8cm}
\begin{minipage}{12cm}
\small
\uppercase{About Stamus Networks}
\vspace{0.3cm}

Stamus Networks believes in a world where defenders are heroes, and a 
future where those they protect remain safe. As defenders face an onslaught
of threats from well-funded adversaries, we relentlessly pursue solutions that
make the defender’s job easier and more impactful. A global provider of
high-performance network-based threat detection and response systems, 
Stamus Networks helps enterprise security teams accelerate their response
to critical threats with solutions that uncover serious and imminent risk
from network activity. Our advanced network detection and response (NDR) 
solutions expose threats to critical assets and empower rapid response.
\vspace{0.8cm}

Copyright \copyright 2022 \hspace{1cm} EB-NWHuntingSuri-082022-1
\end{minipage}
\hspace{0.5cm}
\begin{minipage}{7cm}
\small{
\vspace*{1cm}
\begin{tabular}{p{3.2cm}p{3.6cm}}
\begin{center}
5 Avenue Ingres

75016 Paris

France
\end{center}
&
\begin{center}
450 E 96th St. Suite 500

Indianapolis, IN 46240

United States
\end{center}
\\
\end{tabular}
\begin{center}
Mail: \href{mailto:contact@stamus-networks.com}{\textcolor{white}{contact@stamus-networks.com}}

Web: \href{https://www.stamus-networks.com}{\textcolor{white}{www.stamus-networks.com}}
\end{center}
}
\end{minipage}
    '''
}

if os.getenv('PRINT'):
    latex_elements = {
        'geometry': r'''\usepackage[paperwidth=6.25in, paperheight=9.25in, top=0.625in, bottom=0.625in, left=0.875in, right=0.625in, includefoot, includehead]{geometry}''',
        'pointsize': '10pt',
        'maketitle': r'''\newcommand\sphinxbackoftitlepage{
\vspace*{\fill}
\textit{The Security Analyst’s Guide to Suricata} \\
Copyright @ 2022 by Eric Leblond and Peter Manev \\
Published by Stamus Networks \\
450 E. 96th Street, Suite 500 \\
Indianapolis, IN 46240 \\
This work is licensed under Attribution-ShareAlike 4.0 International (CC BY-SA 4.0) license. \\
Cover Design: Delin Design \\
First printing: October, 2022 \\
Printed in the United States of America \\
Trade hardcover: ISBN: 979-8-9871510-0-6
}
\sphinxmaketitle
        '''
    }
else:
    latex_logo = "img/stamus-logo.png"

latex_additional_files = ["stamus.sty", "img/stamus-logo.png", "img/stamus-background.jpg", "img/stamus-title.jpg", "img/stamus-backcover.jpg"]


epub_cover = ('_static/ebook-cover.jpg', '')

today_fmt = '%B %Y'
