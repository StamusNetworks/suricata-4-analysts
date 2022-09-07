Suricata ecosystem
==================

Some tools will be used throughout the document. They are part of the central tooling around Suricata.

JQ
--

`JQ <https://stedolan.github.io/jq/>`_ is a command line tool that allows users to format, search, and modify JSON objects.

Elastic stack
-------------

The `Elastic stack <https://www.elastic.co/>`_ is a software suite that implements a distributed NoSQL database
(Elasticsearch) with a visualization interface (Kibana) and a log ingestion tool (Logstash). There are other components in the stack that will not be covered here.

Some useful Kibana dashboards have been published by Stamus Networks on `Github <https://github.com/StamusNetworks/KTS7>`_.

Splunk
------

The `Splunk <https://splunk.com>`_ platform is a search, analysis, and visualization engine that features
a really powerful query language.

If you are a Splunk user you may want to get a look at the `Stamus Networks app for Splunk <https://splunkbase.splunk.com/app/5262/>`_
that provides ready to use dashboards and reports for Suricata and Stamus Networks users.


.. index:: Suricata Language Server

.. _suricata-ls:

Suricata Language Server
------------------------

The Suricata Language Server is an implementation of the Language Server Protocol for Suricata signatures. It adds syntax checks and hints as well as auto-completion to your preferred editor once it is configured. Information displayed in the editor is highly valuable when writing Suricata signatures as it
ensures the rules syntax is correct while providing hints about writing performant rules.

Editors that are known to support the Suricata Language Server are Neovim, Visual Studio Code, Sublime Text 3, and Kate, but any editor supporting the Language Server Protocol should also support the Suricata Language Server.

.. image:: img/vscode-sample.png

The Suricata Language Server currently supports auto-completion and advanced syntax checking. Both features use the capabilities of the Suricata deployment available on the system. This means that the list of keywords (with documentation information) and the syntax checking both come from Suricata itself. While this comes at the cost of Suricata needing to be installed on the system, it also guarantees a strict check of signatures with respect to the version of Suricata you are running. Pushing signatures to production will not return a bad surprise as the syntax has already been checked by the same engine. 

Syntax checking is completed when files are saved. A configuration test is started using Suricata, in turn providing errors to the diagnostic. Warnings and hints are also provided by using Suricata's detection engine analysis. This analysis can return warnings and hints about potential issues seen within the signatures.

You can get the `Suricata Language Server <https://github.com/StamusNetworks/suricata-language-server>`_ from GitHub.

