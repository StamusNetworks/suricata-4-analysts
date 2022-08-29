Generic Threat Hunting
======================

Threat Hunting with IDS and NSM data
------------------------------------

Suricata is both an IDS and an NSM tools. It will extract and generate protocol transaction
log independently of alerts. As such, the threat hunter has to find the type of events where getting
result on the data is making the more sense.

Let's take two examples of Indicator Of Compromise (IOC):

- a SMB user name created by a threat actor when he has taken control of an Active Directory. Let's say this username is `pandabear`.
- a domain that is a not so commonly used cloud provider. Let's say the domain is `sovereigncloud.eu`

What is common to both IOC is that first thing to do is to query the
NSM data to see if this IOC have been seen in the network.

For `pandabear` we can do two queries (using Splunk syntax), one to match in the SMB logs and the other one
in the Kerberos logs:

 - `event_type=smb AND smb.ntlmssp.user=pandabear`
 - `event_type=krb5 AND krb5.cname=pandabear`

For the domain, we can do queries on DNS (looking for the query), TLS (one Server Name Indication) and HTTP (looking for the hostname):

 - `event_type=dns AND dns.query.rrname=sovereigncloud.eu`
 - `event_type=tls AND tls.sni=sovereigncloud.eu`
 - `event_type=http AND http.host=sovereigncloud.eu`

In the first case, we are really in trouble if ever the IOC is seen in the organization as the stage of the compromise is advanced
and because `pandabear` is not likely a regular user. In the second, seeing the IOC is just
an indicator as we can have users of this cloud provider and we may need to discriminate among them by doing more investigation.

So for the domain, a regular check in the NSM data may be enough but for the username we may want to switch faster to
incident response. Adding IDS signatures to detect this username if ever it appears may then be a good solution ::

 alert smb any any -> $HOME_NET any (msg:"pandabear"; smb.ntlmssp_user; content:"pandabear"; ...
 alert krb5 any any -> $HOME_NET any (msg:"pandabear"; krb5.cname; content:"pandabear"; ...

Please note that the first signature will require Suricata 7.0 and that dataset is a far better way to match IOCs with Suricata signatures.

To summarize this example, because Suricata is both an IDS and an NSM, there is multiple complementary approach
when doing threat hunting with Suricata.


Correlation using flow_id
-------------------------

Suricata does flow tracking over most TCP/IP protocols. In the case
of TCP this is a  direct mapping of flows to TCP sessions. In the case of UDP,
this is done by looking at the IP information (source IP and port and 
destination IP and port) and applying a timeout logic.

So a flow tracks what is happening on a communication between a client and
a server.

.. index:: flow_id

All IP events contain a `flow_id` key that is the same for all events in a single flow.
This allow to group all events 

An example seen in jq on a simple HTTP request. jq is also used here to reformat the events ::

  jq 'select(.flow_id==1541199918082444)|{"time": .timestamp, "type": .event_type, "src_ip":.src_ip, "src_port": .src_port, "dest_ip": .dest_ip, "dest_port": .dest_port}' -c eve.json
  {"time":"2017-07-24T15:54:12.716673+0200","type":"http","src_ip":"10.7.24.101","src_port":49163,"dest_ip":"216.239.38.21","dest_port":80}
  {"time":"2017-07-24T15:56:28.177134+0200","type":"fileinfo","src_ip":"216.239.38.21","src_port":80,"dest_ip":"10.7.24.101","dest_port":49163}
  {"time":"2017-07-24T16:15:05.777324+0200","type":"flow","src_ip":"10.7.24.101","src_port":49163,"dest_ip":"216.239.38.21","dest_port":80

We have only three events here:

 - an HTPP requests
 - a file information event (analysis of the data of the transferred file)
 - a flow entry containing the packets and bytes accounting as well as the duration of the flow

The flow event is generated once the flow is timeouted by Suricata.

Some flows can have much more events if the protocol (like SMB) is doing a lot of transactions
on a single flow.
 
Learning datasets
-----------------

At first look, the `dataset <https://suricata.readthedocs.io/en/latest/rules/datasets.html>`_ feature belongs to the IDS world (see :ref:`dataset-ioc` for example) as it
provides matching on a list of elements. But `dataset` can be enriched from the packet path and this
means it can be used to store first seen of metadata.

For example, to collect all internal HTTP user agents ::

  alert $HOME_NET any -> any any (msg:"new agent"; http.user_agent; \\
    dataset:isset,http-ua,type string, state /var/lib/http-ua.lst; \\

Every time Suricata will detect a HTTP user agent that has never been seen on the network by Suricata, it will trigger
an alert. These events can be used to build a list of first seen items for all the field that can be matched
with a sticky buffer.

In our signature, the file `/var/list/http-ua.lst` is used to store the state. Suricata will dump the content
of the list it did build into memory to the file (as a base64 string in our case). This ensures that
in case of Suricata restart, no new events will be generated.
