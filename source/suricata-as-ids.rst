IDS features
============

Suricata rule language 
----------------------

Suricata rule language is derived from Snort rule language from 2010 and it has evolved since to become
a separate language sharing a common root.

`Suricata documentation <https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Rules>`_ is really complete
with regards to signature language and keywords and is the ultimate reference.

.. index:: Signature

Anatomy of a signature
----------------------

A signature has 3 parts:
 
 * A keyword for the action: alert, drop, pass, reject
 * IP options to indicate the characteristics of the IP flow
 * Match and information for the signature

Let's take an example ::

 alert http any any -> any any (msg:"http"; \
   http.host; content:"suricata.io"; \
   sid:1; rev;1)

Here Suricata will generate an alert when there is a flow where HTTP application
layer has been identified and when the HTTP host in the request contains ``suricata.io``.
``msg`` is the text that will be used as message in the alert event. The ``sid`` keyword
is the identifier of the signature (must be unique in the ruleset) and ``rev`` is the version
of the signature.

Let's take a more complete example where we want the flow to be from the internal network
(identified by the variable $HOME_NET) to the outside world (identified by the variable $EXTERNAL_NET)
and with destination port ``8080`` ::

 alert http $HOME_NET any -> $EXTERNAL_NET 8080 (msg:"http"; \
   http.host; content:"suricata.io"; \
   sid:1; rev;1)


Suricata rule keywords
----------------------

Types of keywords
~~~~~~~~~~~~~~~~~

There are 3 types of matching keywords:

 * Sticky buffer keywords: the one to be preferred for performance and ease of read
 * Content modifier: they set the context to the previous content match
 * The keyword value: simple content match on a field

It is recommended to only use sticky buffer keywords in newly written rules.

.. index:: Sticky Buffer
Sticky buffer keywords
~~~~~~~~~~~~~~~~~~~~~~

The sticky buffer keyword set the context for the next content matches. For example ::

 http.host; content:"www"; content:"toto"; pcre:"/toto.[com|org]$/"; \
 http.method; content:"GET";

In this case, the host field in HTTP header will match ``www`` and ``toto`` (via the content keywords)
and do a regular expression match to detect the domains. Then there is a switch of context
to the HTTP method and a match on GET on the method is done.

.. index:: Content Modifier
Content modifiers keywords
~~~~~~~~~~~~~~~~~~~~~~~~~~

The content modifier keywords alter the context of the previous content keyword. As a
result the keywords need to be repeated. So if we want to implement the previous example,
we will need to have ::

 content:"www"; http_host; content:"toto"; http_host; pcre:"/toto.[com|org]$/W"; \
 content:"GET"; http_method;

Please note that in addition to the repetition of the keyword a modifier (here ``W``)
has been added to the regular expression match to indicate the match has to be done
on the HTTP host.

Getting keywords from Suricata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can use the following commands ::

 suricata --list-keywords
 =====Supported keywords=====
 - sid
 - priority
 - rev
 - classtype
 - app-layer-protocol

Information about a specific keyword can be obtained via ::

 suricata --list-keywords=http.host
 = http.host =
 Description: sticky buffer to match on the HTTP Host buffer
 Features: No option,sticky buffer
 Documentation: https://suricata.readthedocs.io/en/latest/rules/http-keywords.html#http-host-and-http-raw-host

And a full export of the keywords in CSV format can be generated with ::

 suricata --list-keywords=csv
 name;description;app layer;features;documentation
 sid;set rule ID;Unset;none;https://suricata.readthedocs.io/en/latest/rules/meta.html#sid-signature-id;
 priority;rules with a higher priority will be examined first;Unset;none;https://suricata.readthedocs.io/en/latest/rules/meta.html#priority;
 rev;set version of the rule;Unset;none;https://suricata.readthedocs.io/en/latest/rules/meta.html#rev-revision;
 classtype;information about the classification of rules and alerts;Unset;none;https://suricata.readthedocs.io/en/latest/rules/meta.html#classtype;




