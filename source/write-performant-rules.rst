.. _performant-rules:

=================================
Writing performant Suricata rules
=================================

Suricata detection engine optimizations
=======================================


The detection engine optimization challenge
-------------------------------------------

In demanding enterprise environments, Suricata must operate at very high network speeds -- often between 40Gbps and 100Gbps -- with the full ETPro ruleset loaded. That ruleset is approximately 60,000 signatures, and in order to keep up with line rate, Suricata must inspect all those packets at a rate of 3,333,333 packets per second (when operating at 40Gbps).

So, at 40Gbps there is a budget of .000000000005 seconds per rule. And in this .005 ns per rule, Suricata must do protocol analysis, content matching, and execute regular expressions.

In a typical 3GHz CPU, we have a CPU cycle of 3 ns. As a result, using a brute force approach in the detection engine is 3 orders of magnitude too little, even if a test takes only a single cycle.

Thus, some serious optimizations are needed. Scaling via multithreading to use all cores on the system is a key point here, and Suricata does this very well. But even on a one hundred core system, it will only lead to a 100 factor improvement, and this still leaves us an order of magnitude below the bare minimum needed for the task.

Running load balancing on the CPU is incredibly important, but we still cannot address the 60,000 rules. In this case, we would need to reduce the number of rules processed. Unfortunately, running fewer rules will reduce the threat coverage, so we need a better solution.


Grouping signatures
-------------------

This initial approach is quite simple: why should we evaluate a rule on a UDP flow if we are currently inspecting a TCP packet? By doing a protocol split, we can, in a perfect case, divide the number of signatures to evaluate by two.

While we are at it, we can group signatures by protocol port, group network parameters into a tree, and place groups of signatures in the leafs.

This is an interesting first step, but I'm sure some readers are already concerned about the fact that everything in their network is HTTP or TLS. Thus, they have only 2 used groups.

Something else is needed.

.. index:: Multi Pattern Matching


Multi pattern matching
----------------------

Since we can not differentiate on the IP parameters, we need to go higher in the protocol stack to complete the task; however, an alert can match on an HTTP user agent or on file data transferred over SMB. Given the complexity of the fields we are matching on, we cannot do an implementation of the tree. 

So let's take one step back. In this case, we are pattern matching on one buffer (HTTP user agent, file data, etc...) and would have a wonderful
increase in performance if we could have an automatic tree built up for the patterns we are looking for
on this buffer.

This type of algorithm is named multi pattern matching (MPM) and the most famous implementation
is called `Aho–Corasick algorithm <https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm>`_.

This method allows for a really effective split of signatures.

First, Suricata separates the signatures by IP parameters. Then, it looks at the fast pattern buffer (which has been selected for use with the multi pattern algorithm). There can be only one buffer in order to guarantee a perfect partition of the ruleset. Once the MPM algorithm has returned, there
will be only a small subset of signatures to evaluate. Ideally, if the pattern is well chosen, Suricata could have just a single signature to evaluate.

Let's use this signature as example ::

  alert http any any -> any any (msg:"Bad Agent"; http.user_agent; content: "Winhttp"; fast_pattern; startswith; pcre:"/^Winhttp [0-9]+\/[0-9]+/"; sid:1;)

The evaluation of this signature by Suricata will be as follows:

It will be attached to the set of signatures that have the HTTP user agent as the fast pattern buffer. As a result, the `Winhttp` content match will be evaluated during the MPM phase with all the other matches. One pass algorithm to rule them all. If there is ever a match, the signature will be fully evaluated, content will be checked (which starts with modification), and the regular expression `pcre:"/^Winhttp [0-9]+\/[0-9]+/"` will be verified. So, if `Winhttp` is an efficient differentiator among the HTTP user agent's value, Suricata might have just one signature to fully evaluate instead of the original 60000.

This approach allows Suricata to analyze the full ruleset in a way that is not dependent on the number of signatures. This is dependent on whether or not the signature are correctly written. For example, we cannot have half of them using `Mozilla` as fast pattern buffer on the HTTP user agent because it will result in evaluating a huge number of signatures for each HTTP request since the ` Mozilla` string is present in the HTTP user agent of most common browsers.


Testing performance and correctness of written rules
====================================================

Suricata provides a set of tools to help users write correct rules.

.. index:: Engine analysis


Engine analysis
---------------

Simply run the following command: ::

  suricata -S mynew.rules -l /tmp/analysis --engine-analysis

If inputted correctly, you will receive information about the syntax of the rules ::

  ls -l /tmp/analysis/
  total 16
  -rw-r--r-- 1 eric eric    0 Feb 17 18:58 eve.json
  -rw-r--r-- 1 eric eric    0 Feb 17 18:58 fast.log
  -rw-r--r-- 1 eric eric  733 Feb 17 18:58 rules_analysis.txt
  -rw-r--r-- 1 eric eric  643 Feb 17 18:58 rules_fast_pattern.txt
  -rw-r--r-- 1 eric eric  665 Feb 17 18:58 rules.json
  -rw-r--r-- 1 eric eric    0 Feb 17 18:58 stats.log
  -rw-r--r-- 1 eric eric 2314 Feb 17 18:58 suricata.log

Information is provided in the files ``rules_analysis.txt`` and ``rules_fast_pattern.txt``. In the first one, we can see a previous signature and a variant: ::

  -------------------------------------------------------------------
  Date: 17/2/2021 -- 19:30:28
  -------------------------------------------------------------------
  == Sid: 1 ==
  alert http any any -> any any (msg:"Bad Agent"; http.user_agent; content: "Winhttp"; fast_pattern; startswith; pcre:"/^Winhttp [0-9]+\/[0-9]+/"; sid:1;)
      Rule matches on http user agent buffer.
      App layer protocol is http.
      Rule contains 0 content options, 1 http content options, 0 pcre options, and 1 pcre options with http modifiers.
      Fast Pattern "Winhttp" on "http user agent (http_user_agent)" buffer.
      Warning: TCP rule without a flow or flags option.
               -Consider adding flow or flags to improve performance of this rule.
  
  == Sid: 2 ==
  alert http any any -> any any (msg:"Bad Agent, bad perf"; http.user_agent; pcre:"/^Winhttp [0-9]+\/[0-9]+/"; sid:2;)
      Rule matches on http user agent buffer.
      App layer protocol is http.
      Rule contains 0 content options, 0 http content options, 0 pcre options, and 1 pcre options with http modifiers.
      Warning: TCP rule without a flow or flags option.
               -Consider adding flow or flags to improve performance of this rule.

What we see here is that the first signature has a fast pattern and missed some options on TCP flow. For the second signature, where
there is just a regular expression, we can see that there is no fast pattern and that the TCP flow options are also missing. 

For the fast pattern analysis there is ::

  -------------------------------------------------------------------
  Date: 17/2/2021 -- 19:30:28
  -------------------------------------------------------------------
  == Sid: 1 ==
  alert http any any -> any any (msg:"Bad Agent"; http.user_agent; content: "Winhttp"; fast_pattern; startswith; pcre:"/^Winhttp [0-9]+\/[0-9]+/"; sid:1;)
      Fast Pattern analysis:
          Fast pattern matcher: http user agent (http_user_agent)
          Flags: Depth
          Fast pattern set: yes
          Fast pattern only set: no
          Fast pattern chop set: no
          Original content: Winhttp
          Final content: Winhttp
  
  == Sid: 2 ==
  alert http any any -> any any (msg:"Bad Agent, bad perf"; http.user_agent; pcre:"/^Winhttp [0-9]+\/[0-9]+/"; sid:2;)
      Fast Pattern analysis:
          No content present

This confirms the fact that the second rule will trigger an evaluation of the regular expression for all the http requests (where there is an http user agent).

Information about the structure of the signature is also available in ``rules.json``. It is less human friendly, but follows the evolution of Suricata's detection engine more closely. For example, this output is used by the :ref:`Suricata Language Server <suricata-ls>` to build advanced analysis of the signatures file.

.. _profiling-info:

.. index:: Rules profiling


Rules profiling
---------------

The information provided by Suricata in the engine analysis is really valuable, but it is often better to see the impact on a real run. To do so, there is a profiling system inside Suricata that needs to be activated during the build and can be setup in the configuration.

To build it you need to add ``--enable-profiling`` to the ``./configure`` command line. Suricata performance will be impacted and this should not be used in production, but you will have a ``rule_perf.log`` file in your log directory with performance information.

.. code-block:: JSON

  {
    "timestamp": "2021-02-17T19:41:56.012543+0100",
    "sort": "max ticks",
    "rules": [
      {
        "signature_id": 2,
        "gid": 1,
        "rev": 0,
        "checks": 1628,
        "matches": 4,
        "ticks_total": 2173774,
        "ticks_max": 49498,
        "ticks_avg": 1335,
        "ticks_avg_match": 23204,
        "ticks_avg_nomatch": 1281,
        "percent": 93
      },
      {
        "signature_id": 1,
        "gid": 1,
        "rev": 0,
        "checks": 4,
        "matches": 4,
        "ticks_total": 149520,
        "ticks_max": 41118,
        "ticks_avg": 37380,
        "ticks_avg_match": 37380,
        "ticks_avg_nomatch": 0,
        "percent": 6
      }
    ]
  }

Here, we see that signature 2 did take 93% of CPU cycles compared to the second one at 6%. This was expected as we evaluated the regular expression for all HTTP requests. An interesting observation is that ``ticks_avg_nomatch`` is 0 for the signature with fast pattern. The reason is that when there is no ``Winhttp`` string in the HTTP user agent the MPM algorithm simply skips the evaluation of the rules and hence its cost is null. With the incorrect signature we can see that the cost is 1281 ticks for every match attempt, and we have 4 ``checks`` for signature 1 and 1628 for signature 2. Hence, the performance ratio is calculated.

A perfect signature should have zero in ``ticks_avg_nomatch`` and should have a really low ``ticks_avg_match``. The first point being the most important as it means the multi pattern matching on the signature is not triggering when the signature is not matching. This will be the case when the pattern used in MPM is discriminative enough that no other signatures are using it.


Guideline for performant rules
==============================


Trigger multi pattern matching
------------------------------

This is the main recommendation:

When writing a rule you need to find a way to trigger MPM in an efficient way. This means the signature must have a content match on a pattern that is on a differentiator. It should be almost unique in the ruleset so it reduces the signature group to the lowest number possible.

In our previous example, we used ``http.user_agent; content: "Winhttp";`` because the string ``Winhttp`` is not common among HTTP user agents. This guaranteed us an efficient prefiltering by the MPM engine. As we have seen previously in the profiling output, all the checks done on the signature have been successful. The rest of the filters were just confirmation filters to avoid potential false positives.


Prefilter everything
-------------------------

This is just a reformulation of the previous exigency. Even if the real match is a nasty regular expression, you still need to find the longest string possible with an efficient differentiator capability.

.. _dataset-ioc:


Matching on IOCs
----------------

In a lot of cases, indicators of compromises comes as a list of domains, IPs, and user agents to match against the produce data. An already seen approach consists of generating a rule for each indicator of compromise (IOC).

This will match, but the performance impact will be huge.

If you have to match on an IP list, it is better to use the IP reputation system via the `iprep <https://suricata.readthedocs.io/en/latest/rules/ip-reputation-rules.html>`_ keyword that allows a fast match and one single rule for any number of IP addresses.

The same can be done for file hash via the keywords `filemd5 <https://suricata.readthedocs.io/en/latest/rules/file-keywords.html?highlight=filemd5#filemd5>`_, `filesha1 <https://suricata.readthedocs.io/en/latest/rules/file-keywords.html?highlight=filemd5#filesha1>`_, and `filesha256 <https://suricata.readthedocs.io/en/latest/rules/file-keywords.html?highlight=filemd5#filesha256>`_ that match on the list of file hashes. 

For example, with a list of sha256 file hashes named ``known-bad-sha256.lst``, one can use the following signatures: ::

  alert smb any any -> any any (msg:"known bad file on SMB"; filesha256:"known-bad-sha256.lst"; sid:1; rev:1;)
  alert nfs any any -> any any (msg:"known bad file on NFS"; filesha256:"known-bad-sha256.lst"; sid:2; rev:1;)
  alert http any any -> any any (msg:"known bad file on HTTP"; filesha256:"known-bad-sha256.lst"; sid:3; rev:1;)
  alert ftp-data any any -> any any (msg:"known bad file on FTP"; filesha256:"known-bad-sha256.lst"; sid:4; rev:1;)
  alert smtp any any -> any any (msg:"known bad file on SMTP"; filesha256:"known-bad-sha256.lst"; sid:5; rev:1;)

Introduced in Suricata 5.0, `dataset <https://suricata.readthedocs.io/en/latest/rules/datasets.html>`_ is filling the gap for over existing IOCs. It can be used with any sticky buffers. For example, if you have a list of HTTP user agents in ``bad-http-agent.lst``, you can use a signature similar to the following ::

  alert http any any -> any any (msg:"bad user agent"; \
      http.user_agent; dataset:isset,bad-http-agent,type string,load:http-user-agent.lst,memcap:1G,hashsize:1000000; \
      sid 6; rev:1;)

Please note: in the case of a dataset with string type, the set needs to first be encoded to base64 (without the trailing
character).


Real life example
=================

When `Sunburst <https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html>`_ was made public, a set of signatures was soon created to detect some of the offensive tools used by Fireeye. Among them we had this Snort-like signature: ::

  alert tcp any $HTTP_PORTS -> any any (msg:"Backdoor.HTTP.BEACON.[CSBundle MSOffice Server]"; content:"HTTP/1."; depth:7; \
        content:"{\"meta\":{},\"status\":\"OK\",\"saved\":\"1\",\"starttime\":17656184060,\"id\":\"\",\"vims\":{\"dtc\":\""; \
        sid:25887; rev:1;)

This signature has some serious problems when run inside Suricata. The engine analysis gives the following result: ::

    Rule matches on packets.
    Rule matches on reassembled stream.
    Rule contains 2 content options, 0 http content options, 0 pcre options, and 0 pcre options with http modifiers.
    Fast Pattern "{\x22meta\x22:{},\x22status\x22:\x22OK\x22,\x22saved\x22:\x221\x22,\x22starttime\x22:17656184060,\x22id\x22:\x22\x22,\x22vims\x22:{\x22dtc\x22:\x22" on "payload and reassembled stream" buffer.
    Warning: TCP rule without a flow or flags option.
             -Consider adding flow or flags to improve performance of this rule.
    Warning: Rule has depth/offset with raw content keywords.  Please note the offset/depth will be checked against both packet payloads and stream.  If you meant to have the offset/depth checked against just the payload, you can update the signature as "alert tcp-pkt..."
    Warning: Rule is inspecting both the request and the response.

The first warning is about the lack of options because the signature is not checking the direction (to the client in our case) or ensuring that the flow is established. The second warning is more interesting because it warns us that Suricata will inspect the content twice: one time for every TCP packet and one time for each TCP stream. And finally, the third warning mentions that the signature could inspect request and response (in the event that the  HTTP_PORTS variable is broad).

But the presence itself of HTTP_PORTS is a problem. If the attacker ever changes the port of the web server to something not covered by the variable we will miss the detection. A typical Suricata signature will fix that by making use of the port independent protocol detection. 

This can simply be done by doing: ::

  alert http any any -> any any

As we are looking at the stream to the client, we can add `flow:established,to_client` to the rule

If we run the modified rules through the detection engine, we see: ::

    Warning: Rule app layer protocol is http, but content options do not have http_* modifiers.
             -Consider adding http content modifiers.

Yes, we are still doing TCP stream matching on a signature on the HTTP protocols instead of matching inside the fields of the HTTP protocol.

Let’s look at the first content match: ::

  content:"HTTP/1."; depth:7;

We are matching on the beginning of the server answer because HTTP_PORTS was on the left in the initial signature. So what we have now is a confirmation that the answer starts by the `HTTP/1.` string. A potential solution is to use the keyword `http.response_line`: ::

  http.response_line; content:"HTTP/1."; depth:7;

The second match is the following: ::

  content:"{\"meta\":{},\"status\":\"OK\",\"saved\":\"1\",\"starttime\":17656184060,\"id\":\"\",\"vims\":{\"dtc\":\"";

We don’t have access to the packet, but it looks like a good guess to assume that the data was in the response body from the server. 

So now we can do: ::

  http.response_body; content:"{\"meta\":{},\"status\":\"OK\",\"saved\":\"1\",\"starttime\":17656184060,\"id\":\"\",\"vims\":{\"dtc\":\"";

We end up with the following rules that have no warning: ::

  alert http any any -> any any (msg:"Backdoor.HTTP.BEACON.[CSBundle MSOffice Server]"; \
        http.response_line; content:"HTTP/1."; depth:7; \
        http.response_body; content:"{\"meta\":{},\"status\":\"OK\",\"saved\":\"1\",\"starttime\":17656184060,\"id\":\"\",\"vims\":{\"dtc\":\""; \
        flow:established,to_client; sid:25887; rev:1; ) 

The initial signature was published by Proofpoint in the emerging threats ruleset, but it was fully rewritten the next day by the Proofpoint team to instead read: ::

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS [Fireeye] Backdoor.HTTP.BEACON.[CSBundle MSOffice Server]"; \
        flow:from_server,established; \
        http.response_line; content:"HTTP/1."; depth:7; \
        file.data; content:"|7b 22|meta|22 3a 7b 7d 2c 22|status|22 3a 22|OK|22 2c 22|saved|22 3a 22|1|22 2c 22|starttime|22 3a|17656184060|2c 22|id|22 3a 22 22 2c 22|vims|22 3a 7b 22|dtc|22 3a 22|"; fast_pattern; \
        reference:url,github.com/fireeye/red_team_tool_countermeasures; \
        classtype:trojan-activity; sid:2031279; rev:3; \
        metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2020_12_08, deployment Perimeter, signature_severity Major, updated_at 2020_12_12;)
 
As expected, we have no warnings when doing the engine analysis: ::

    Rule matches on http server body buffer.
    Rule matches on http response line buffer.
    App layer protocol is http.
    Rule contains 0 content options, 2 http content options, 0 pcre options, and 0 pcre options with http modifiers.
    Fast Pattern "{\x22meta\x22:{},\x22status\x22:\x22OK\x22,\x22saved\x22:\x221\x22,\x22starttime\x22:17656184060,\x22id\x22:\x22\x22,\x22vims\x22:{\x22dtc\x22:\x22" on "http response body, smb files or smtp attachments data (file_data)" buffer.
    No warnings for this rule.

This signature has some differences to our attempt. It uses `file.data` to match in the `http.response_body` but it is quite the same thing. It also forces the `fast_pattern` on this part of the content which should not be necessary but is always safe to do.

The rest is metadata and information. We first have the reference: ::

 reference:url,github.com/fireeye/red_team_tool_countermeasures;

Then the classification: ::

 classtype:trojan-activity;

And finally the metadata: ::

  metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint,\
        created_at 2020_12_08, deployment Perimeter, signature_severity Major, updated_at 2020_12_12;

These pieces of metadata are important because we will find them in the alert event as shown on :numref:`alert-metadata`

.. _alert-metadata:

.. figure:: img/alert-metadata.png
   :scale: 70 %

   Metadata in the alert event

This allows efficient and flexible classifications of the alert events that can be used in queries and the interface. For example, it can be used to present the variety of alerts seen in a system like the one shown on :numref:`metadata-panel`

.. _metadata-panel:

.. figure:: img/alert-sig-metadata.png

   Panels using signature metadata in Scirius

The result is shown in the `Scirius <https://github.com/StamusNetworks/scirius>`_ interface but any data lake that understands JSON will be able to build the same type of visualization.

Or for the created and updated date, a nice way to see which recent signatures did fire on the probes like shown on :numref:`signatures-ordered`

.. _signatures-ordered:

.. figure:: img/signatures-ordered.png

   Signatures ordered by creation date in Scirius


Fixing warnings from Suricata Language Server
=============================================

The :ref:`Suricata Language Server <suricata-ls>` uses Suricata features to display warning and hints in IDE and text editors that support LSP.
Some of the warnings may appear confusing at first, so let's take a tour to understand them and discover how to fix them.


Directionality warning
----------------------

.. figure:: img/directionality-warning.png

   Directionality warning seen in Neovim

The signature ::

 alert tcp any any -> any any (msg:"toto out"; content:"toto"; sid:1; rev:1;)

triggers the following warning: 'Rule inspect server and client side, consider adding a flow keyword`

In this signature, the `content` match has no sticky buffer or content modifier attached. As a result, the match is done on the TCP stream data. TCP stream goes two ways, so the inspection will be done for all data going to the server and all data going to the client. In most cases, this is not what we
want to match as we usually know that the pattern should be in a client or server message.

So the correct signature would look something like this: ::

  alert tcp any any -> any any (msg:"toto out"; content:"toto"; \\
            flow:established,to_server; \\
            sid:1; rev:1;)

By doing this, the inspection will only be done on the packet going to the server. As a result, the inspection work is cut in half as we are just inspecting one way.


Mixed content
-------------

.. figure:: img/mixed-content.png

   Mixed content warning seen in Neovim


The signature ::

 alert http any any -> any any (msg:"Doc reader with curl"; \\
            content:"/rtfm"; \\
            http.user_agent; content:"curl"; \\
            sid:2; rev:1;)

triggers the following warning: 'Application layer "http2" combined with raw match, consider using a match on application buffer'

In the signature the first match `content:"/rtfm"` is done on TCP stream data as there is no sticky buffer or content modifier associated
with it. But the second match, `http.user_agent; content:"curl";`, is done on the HTTP user agent buffer. This setup is not natural as it
is better to work on one of the HTTP fields for all the matches. If we look at the first match, it looks like an URL.

So the correct signature would look something like ::

 alert http any any -> any any (msg:"Doc reader with curl"; \\
            http.uri; content:"/rtfm"; \\
            http.user_agent; content:"curl"; \\
            sid:2; rev:1;)


Missing HTTP keywords
---------------------

.. figure:: img/missing-http.png

    Missing HTTP keywords warning seen in Neovim

The signature ::

 alert http any any -> any any (msg:"Doc reader"; content:"GET /rtfm"; sid:3; rev:1;)

triggers the following warning: 'pattern looks like it inspects HTTP, use http.request_line or http.method and http.uri instead for improved performance'

In this signature, we have a single content match that searched for 2 words and looks like a part of an HTTP request. Suricata
did detect that and is warning that it would be better to use proper HTTP keywords. This will be better for multiple reasons. First, the HTTP
keywords match on normalized strings and it will improve the resilience of the signature to evasion compared to a simple content match.
Second, it is far more accurate to use matches on HTTP fields. In this particular case, the signature will alert on any HTTP stream
that contains `GET /rtfm`. As a consequence, it will, for example, alert if the signature file is downloaded over HTTP.

So the correct signature would look more like this: ::

 alert http any any -> any any (msg:"Doc reader with curl"; \\
            http.method; content: "GET"; \\
            http.uri; content:"/rtfm"; \\
            sid:2; rev:1;)

We have a match on the HTTP method followed by a match on the URI.

.. _rules-perfomance-improvement:


Performance Improvement process
===============================

There are always multiple ways to write a rule. The variants depend on what you are going to match on and what methods are being used for that
match. For example, the two following rules may match the same way on a sample, but could have varying levels of performance: ::

 alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Test - Rule variant - 1"; \\
            flow:established,to_server; \\
            http.method; content:"GET"; http.uri; \\
            content:"lookforthis"; \\
            classtype:command-and-control; sid:1000002; rev:1; \\
            metadata:created_at 2022_08_10, updated_at 2022_08_10;)
 
 alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Test - Rule variant - 2"; \\
            flow:established,to_server; urilen:25; \\
            http.method; content:"GET"; http.uri; \\
            content:"lookforthis"; http.cookie; content:"lookforthat"; \\
            classtype:command-and-control; sid:1000003; rev:1; \\
            metadata:created_at 2022_08_10, updated_at 2022_08_10;)

To validate the performance of a rule and select the best one, it must be be ran and evaluated over both relevant and non relevant pcaps so the impact
of the rule can be seen on all types of traffic. To do so, you must run the rule through both types of pcaps while having `rule-profiling` enabled.

The signature needs to be complete (See steps in :ref:`Signature writing process <write-signature>`) before you can test its performance.


#. Verify the rule syntax with Suricata Language Server or run Suricata with `--engine-analysis`
#. Use a pcap with relevant traffic

   - Run the pcap and the rules with suricata that has rules profiling enabled. A relevant section in the suricata `suricata.yaml` config can be used to adjust sorting or to enable text and JSON outputs
   - Review the results in `rule_perf.log` and make further adjustments as needed. See :ref:`Profile information <profiling-info>` for details

#. Use a pcap with non relevant traffic.

   - Run with rules profiling
   - Review the results

The winning rule is the one with the lowest impact to performance on the relevant traffic and ideally done not appear (aka is not being evaluated at all) in the non-relevant traffic pcap run.

