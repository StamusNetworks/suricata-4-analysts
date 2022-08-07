Suricata ecosystem
==================

Some tools will be used through out the document. They are part of the tooling
around Suricata.

JQ
--

`JQ <https://stedolan.github.io/jq/>`_ is a command line tool that allow to format, search and modify JSON object.

Elastic stack
-------------

The `Elastic stack <https://www.elastic.co/>`_ is a set of software that implements a distributed NoSQL database
(Elasticsearch) with a visualization interface (Kibana) and a log ingestion tool (Logstash). There is a lot of
other components in the stack that will not be covered here.

Some useful Kibana dashboards have been published by Stamus Networks on `Github <https://github.com/StamusNetworks/KTS7>`_.

Splunk
------

The `Splunk <https://splunk.com>`_ platform is a search, analysis and visualization engine that features
a really powerful query language.

If you are a Splunk user, you may want to get a look at `Stamus Networks app for Splunk <https://splunkbase.splunk.com/app/5262/>`_
that provides ready to use dashboards and reports for Suricata and Stamus Networks users.

.. _suricata-ls:

Suricata Language Server
------------------------

Suricata Language Server is an implementation of the Language Server Protocol for Suricata signatures.
It adds syntax check and hints as well as auto-completion to your preferred editor once it is configured.
Information displayed in the editor is really valuable when writing Suricata signatures as it
ensures the rules syntax is correct and it provides hint about writing performant rules.

Editors that are known to support the Suricata Language Server are Neovim, Visual Studio Code,
Sublime Text 3, Kate but any editor supporting the Language Server Protocol should support it.

.. image:: img/vscode-sample.png

Suricata Language Server currently supports auto-completion and advanced syntax checking. Both features are
using the capabilities of the Suricata available on the system. This means that the list of keywords (with
documentation information) is coming for Suricata itself and it is the same for the syntax checking. This
comes at the cost to have Suricata installed on your system but at the same time, it guarantees a strict
checking of signatures with respect to the Suricata version you are running. Pushing signatures to
production will not result in bad surprise as the syntax has already been checked by the same engine.

Syntax checking is done when saving the files. A configuration test is started using Suricata. This
is providing errors to the diagnostic. Warnings and hints are also provided by using a
detection engine analysis done by Suricata. This is returning warnings and hints about the potential
issues seen of the signatures.

You can get the `Suricata Language Server <https://github.com/StamusNetworks/suricata-language-server>`_ from GitHub.


