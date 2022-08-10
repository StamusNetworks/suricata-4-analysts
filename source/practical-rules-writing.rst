Practical rule writing
=======================

Methodology
-----------

There are a few techniques that greatly improve the rule writing experience.

Use a PCAP file
~~~~~~~~~~~~~~~

Writing a rule is an iterative process, so it is easier to write the rule using a PCAP
file that can be replayed multiple times instead of doing it on live traffic.

So, try to capture a PCAP trace of the behavior you want to inspect, then
you can replay it when your signature needs to be tested.

To replay the pcap, you can use something like (create data directory first) ::

 rm data/eve.json
 suricata -r ./trace.pcap -l data/
 cat eve.json | jq 'select(.alert.signature_id==1000000)'

if your signature ID is 1000000.

The 1000000-1999999 range is reserved for internal usage, so it is a good choice.
Contact the `Sid Allocation project <https://sidallocation.org/>`_ if you want
to publish your rules publicly.

Replay with only your rules file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To speed up the writing of a rule, you need tests to be fast. The -S flag is here to help.
Suricata will only load the rules in the file provided after the option. As a result, the run
will take only a few seconds instead of 30 seconds or more if Suricata needs to build a complete
detection engine.

With this option, the testing process becomes ::

 rm data/eve.json
 suricata -r ./trace.pcap -l data/ -S ./my.rules
 cat eve.json | jq 'select(.event_type=="alert")'


Add IP filtering in later stage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is better to write a signature starting with `any any -> any any` then add a filtering like
`$HOME_NET any -> $EXTERNAL_NET any`. The source and destination IP depends of the signature
and the HOME_NET may not be correctly defined with regards to the data in the PCAP file.
The result is that the signature may just not match because of 
that and not because of a complex regular expression you did add in the signature.


Writing a rule - step by step
----------------------------

The following is a suggestion for a process to use when writing signatures:

Get a pcap file
~~~~~~~~~~~~~~~

First step is to get a PCAP file with the content you want to trigger the rule. Don't hesitate to filter out things in the pcap.
For example, if you want to match on a single flow you can do something like ::

 tcpdump -r input.pcap -w work.pcap port 53535 and port 443

where 53535 and 443 are the source and destination ports of the flow you want to match
on. You can also add a few `host` filters in the BPF if the previous command returned
more than one flow.

Now we can use the file `work.pcap` for our tests.

Run the file inside Suricata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By running Suricata without any rules on the file, we can extract all the metadata seen by Suricata ::

 rm data/eve.json
 suricata -r ./trace.pcap -l data/ -S /dev/null
 # explose data/eve.json

In most cases, it will be good enough to get an idea of what fields we should matched on.
As the data are coming from Suricata itself, the string will be exactly what we should use
in the signaure.

If you need more inspection, you can use `Wireshark <https://www.wireshark.org/>`_ to do so.
You can also see Suricata data in Wireshark
by using `Suriwire <https://github.com/regit/suriwire>`_.

Write your signature
~~~~~~~~~~~~~~~~~~~~

We higly recommend using a text editor supported by the :ref:`Suricata Language Server <suricata-ls>` for the editing. 
Using the editor with the Suricata Language Server extension allows you to easily identify errors and take advantage of auto-completion. During the writing phase, this is easier to have a file
containing a single signature.

We can then test if the rule is alerting by running ::

 rm data/eve.json
 suricata -r ./trace.pcap -l data/ -S my.rules -v
 cat eve.json | jq 'select(.event_type=="alert")'

The last command may not even be necessary as by adding `-v` we will have the number of alerts at the end of the output ::

 [9093] 9/8/2022 -- 23:50:47 - (counters.c:871) <Info> (StatsLogSummary) -- Alerts: 1

As mentioned before, the easiest approach is to get an iterative approach here:

 - Start with a simple content match on one of the sticky buffer keywords
 - Add some more contents match if needed
 - complete with a regular expression if needed
 - set up the variable for the IPs (HOME_NET, EXTERNAL_NET for example)
 - add the metadata keyword for more usable data

Between each steps, run suricata to verify that your output is correct.

See the chapter :ref:`Write performant Suricata rules <performant-rules>` for more details and explanation on the steps described
above and especially the :ref:`Performance improvement process <rules-perfomance-improvement>` section.
