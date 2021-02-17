=================================
Writing performant Suricata rules
=================================

Suricata detection engine optimizations
=======================================

The detection engine optimization challenge
-------------------------------------------

Suricata is able to run at speed like 40Gbps with full ETPro ruleset loaded.
This means around 60000 signatures loaded and inspecting as a best case scenario
3,333,333 packets per second.

This means there is a budget of .000000000005 second per rule. And, in this
.005 ns per rule, Suricata must do protocol analysis, content matching and runs regular expression.

With a 3GHz CPU, we have a CPU cycle of 3 ns. So a brute force approach of the detection engine
is 3 orders of magnitude too small even if a test was taking one single cycle.

Thus some serious optimizations are mandatory. Scaling via multithreading to use all core on the system
is a key point here and Suricata does it very well. But on a one hundred core system, it will only lead to a
100 factor improvement and we thus still one order of magnitude below the really bare minimum we need.

Load balancing work on CPU is a key point but we still not can address the
60000 rules. We need less. But doing less will lower the threat coverage
so we need to get beyond that.


Grouping signatures
-------------------

This initial approach is quite simple: why should we evaluate a rule on an UDP flow if we are currently
inspecting a TCP packet. By doing a protocol split we can in a perfect case divide by two the number of signature
to evaluate.

And as we are here, we can also group signatures by protocol port and build a tree where we group
by network parameters and get groups of signatures in the leafs.

This is an interesting first step, but I'm sure some reader are already complaining
about the fact everything in their network is HTTP or TLS. And thus they have only 2 used groups.

Something else is needed.


Multi pattern matching
----------------------

As we can not differentiate on the IP parameters, we need to go higher in the protocol stack to
do the same thing. But, well, an alert can match on HTTP user agent or can match on file data
transfered over SMB. And given the complexity of the fields we are matching on we can not do a
implementation of the tree. But let's take one step back. In all this cases, we are doing
pattern matching on one buffer (HTTP user agent, file data, ...) and we would have a wonderful
performance gain if we could have an automatic tree built up for the patterns we are looking for
on this buffer.

This type of algorithm is name multi pattern matching and the most famous implementation
is called `Aho–Corasick algorithm <https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm>`_.

This method allows a really effective split of signatures.

First 


Testing performance and correctness of written rules
====================================================

Engine analysis
---------------

Get a view  on how bad your rules

Rules profiling
---------------

Get show examples of profiling output

Guideline for performant rules
==============================

Trigger multi pattern matching
------------------------------

Pre filter all the things
-------------------------

Real life example
-----------------

When sunburst was made public a set of signatures was created soon after to detect some of the offensive tools used by Fireeye. Among them we had this snort like signature:

alert tcp any $HTTP_PORTS -> any any (msg:"Backdoor.HTTP.BEACON.[CSBundle MSOffice Server]"; content:"HTTP/1."; depth:7; content:"{\"meta\":{},\"status\":\"OK\",\"saved\":\"1\",\"starttime\":17656184060,\"id\":\"\",\"vims\":{\"dtc\":\""; sid:25887; rev:1;)

This signature has some serious problems when run inside Suricata. The engine analysis gives the following result: ::

    Rule matches on packets.
    Rule matches on reassembled stream.
    Rule contains 2 content options, 0 http content options, 0 pcre options, and 0 pcre options with http modifiers.
    Fast Pattern "{\x22meta\x22:{},\x22status\x22:\x22OK\x22,\x22saved\x22:\x221\x22,\x22starttime\x22:17656184060,\x22id\x22:\x22\x22,\x22vims\x22:{\x22dtc\x22:\x22" on "payload and reassembled stream" buffer.
    Warning: TCP rule without a flow or flags option.
             -Consider adding flow or flags to improve performance of this rule.
    Warning: Rule has depth/offset with raw content keywords.  Please note the offset/depth will be checked against both packet payloads and stream.  If you meant to have the offset/depth checked against just the payload, you can update the signature as "alert tcp-pkt..."
    Warning: Rule is inspecting both the request and the response.

First warning is about the lack of option, signature is not checking the direction (to client in our case) or ensuring the flow is established. Second warning is more interesting because it warns us that Suricata will inspect twice the content, one time for every TCP packet and one time for each TCP stream. And finally the third warning is mentioning that the signature could inspect request and response (if ever HTTP_PORTS variable is broad).

But the presence itself of HTTP_PORTS is a problem. If ever the attacker changes the port of the web server, to something not covered by the variable, we will miss the detection. A typical Suricata signature will fix that by making use of the port independent protocol detection. This can simply be done by doing: ::

  alert http any any -> any any

And as we are looking at the stream to the client, we can add ‘flow:established,to_client’ to the rule

If we run the modified rules through the detection engine, we see ::

    Warning: Rule app layer protocol is http, but content options do not have http_* modifiers.
             -Consider adding http content modifiers.

Yes, we are still doing TCP stream matching on a signature on the HTTP protocols instead of matching inside the fields of the HTTP protocol.

Let’s look at the first content match: ::

  content:"HTTP/1."; depth:7;

We are matching on the beginning of the server answer because HTTP_PORTS was on the left in the initial signature. So what we have is a check that the answer starts by “HTTP/1.” string. A potential solution is to use keyword http.response_line: ::

  http.response_line; content:"HTTP/1."; depth:7;

The second match is the following: ::

  content:"{\"meta\":{},\"status\":\"OK\",\"saved\":\"1\",\"starttime\":17656184060,\"id\":\"\",\"vims\":{\"dtc\":\"";

We don’t have access to the packet but it looks like a good guess to assume that the data was in the response body from the server. So we can do: ::

  http.response_body; content:"{\"meta\":{},\"status\":\"OK\",\"saved\":\"1\",\"starttime\":17656184060,\"id\":\"\",\"vims\":{\"dtc\":\"";

So we end up with the following rules that has no warning ::

  alert http any any -> any any (msg:"Backdoor.HTTP.BEACON.[CSBundle MSOffice Server]"; \
        http.response_line; content:"HTTP/1."; depth:7; \
        http.response_body; content:"{\"meta\":{},\"status\":\"OK\",\"saved\":\"1\",\"starttime\":17656184060,\"id\":\"\",\"vims\":{\"dtc\":\""; \
        flow:established,to_client; sid:25887; rev:1; ) 

Facing the urgency, the initial signature was published by Proofpoint in the emerging threat ruleset but it was fully rewritten the next day by Proofpoint team to: ::

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS [Fireeye] Backdoor.HTTP.BEACON.[CSBundle MSOffice Server]"; \
        flow:from_server,established; \
        http.response_line; content:"HTTP/1."; depth:7; \
        file.data; content:"|7b 22|meta|22 3a 7b 7d 2c 22|status|22 3a 22|OK|22 2c 22|saved|22 3a 22|1|22 2c 22|starttime|22 3a|17656184060|2c 22|id|22 3a 22 22 2c 22|vims|22 3a 7b 22|dtc|22 3a 22|"; fast_pattern; \
        reference:url,github.com/fireeye/red_team_tool_countermeasures; \
        classtype:trojan-activity; sid:2031279; rev:3; \
        metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2020_12_08, deployment Perimeter, signature_severity Major, updated_at 2020_12_12;)
 
As expected, we have no warning when doing the engine analysis: ::

    Rule matches on http server body buffer.
    Rule matches on http response line buffer.
    App layer protocol is http.
    Rule contains 0 content options, 2 http content options, 0 pcre options, and 0 pcre options with http modifiers.
    Fast Pattern "{\x22meta\x22:{},\x22status\x22:\x22OK\x22,\x22saved\x22:\x221\x22,\x22starttime\x22:17656184060,\x22id\x22:\x22\x22,\x22vims\x22:{\x22dtc\x22:\x22" on "http response body, smb files or smtp attachments data (file_data)" buffer.
    No warnings for this rule.

The signature has some differences with our attempt. It uses file.data to match in the http.response_body but it is quite the same thing. It also forces the fast_patter on this part of the content which should not be necessary but is always safe to do.

And the rest is metadata and information. We first have the reference: ::

 reference:url,github.com/fireeye/red_team_tool_countermeasures;

Then come the classification ::

 classtype:trojan-activity;

And then we have the metadata: ::

  metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint,\
        created_at 2020_12_08, deployment Perimeter, signature_severity Major, updated_at 2020_12_12;

These metadata are important because we will find them in the alert event:

.. image:: img/alert-metadata.png

And this allows on one side efficient and flexible classifications of the alert events that can be used in queries and interface. For example, it can be used to present the variety of alerts seen in a system:

.. image:: img/alert-sig-metadata.png

Or for the created and updated date, a nice way to see which recent signatures did fire on the probes:

.. image:: img/signatures-ordered.png

Enhance produced events
=======================

Metadata for classification
---------------------------

As the keys and value in metadata have no constraints (but on formatting), you can define your own semantic and organization if you work on your set of rules.
Extract information


Recent evolution
================

Sticky buffers
--------------

The switch from content modifier to sticky buffers

Datasets
--------

IOC baby


