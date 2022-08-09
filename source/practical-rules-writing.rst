Practical rules writing
=======================

Methodology
-----------

There is a few methods that greatly improves the rules writing experience.

Use a PCAP file
~~~~~~~~~~~~~~~

Writing a rule is an iterative process so it is really easier to work using a PCAP
file instead of doing it on live traffic.

So try to capture a PCAP trace of the behavior you want to inspect, then
you can replay it as soon as your signature needs to be tested.

To replay the pcap, you can use something like (create data directory first) ::

 rm data/eve.json
 suricata -r ./trace.pcap -l data/
 cat eve.json | jq 'select(.alert.signature_id==1000000)'

if your signature ID is 1000000.

Replay with only your rules file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To speed up the writing of a rule, you need tests to be fast. The -S flag is here to help
as Suricata will only load the rules in the file provided after the option. As a result, the run
will be a few seconds instead of 30 seconds or more if Suricata needs to build a complete
detection engine.

With this option, the testing process becomes ::

 rm data/eve.json
 suricata -r ./trace.pcap -l data/ -S ./my.rules
 cat eve.json | jq 'select(.event_type=="alert")'


Add IP filtering later
~~~~~~~~~~~~~~~~~~~~~~

It is better to write a signature starting with `any any -> any any` then add a filtering like
`$HOME_NET any -> $EXTERNAL_NET any`. The source and destination IP depends of the signature
and the HOME_NET may not be correctly defined with regards to the data in the PCAP file.
Result is that the signature may just not match because of
that and not because of a complex regular expression you did add in the signature.


Writing a rules step by step
----------------------------


