Generic Threat Hunting
======================


Threat Hunting with IDS and NSM data
------------------------------------

Suricata is both an IDS and an NSM tool. It will extract and generate protocol transaction logs independently of alerts. As a result, the threat hunter has the responsibility of finding the types of events where searching for results on the data makes the most sense. 

Let's take two examples of an Indicator Of Compromise (IOC):

- an SMB user name created by a threat actor when he has taken control of an Active Directory. Let's say this username is 'pandabear'.
- a domain that is an uncommonly used cloud provider. Let's say the domain is 'sovereigncloud.eu'

What these IOCs have in common is that first thing the threat hunter must do is query the NSM data to see if the IOC has been seen in the network.

For 'pandabear', we can do two queries (using Splunk syntax), one to match in the SMB logs and the other one in the Kerberos logs:

 - `event_type=smb AND smb.ntlmssp.user=pandabear`
 - `event_type=krb5 AND krb5.cname=pandabear`

For the domain, we can do queries on DNS (looking for the query), TLS (one Server Name Indication), and HTTP (looking for the hostname):

 - `event_type=dns AND dns.query.rrname=sovereigncloud.eu`
 - `event_type=tls AND tls.sni=sovereigncloud.eu`
 - `event_type=http AND http.host=sovereigncloud.eu`

In the first example, we are really in trouble if the IOC is seen in the organization because the stage of the compromise is advanced, and because 'pandabear' is not likely a regular user. In the second, seeing the IOC is just an indicator because we can have users of this cloud provider, causing a  need to discriminate among them further by doing more investigation.

For the domain, a regular check of the NSM data may be enough. For the username, on the other hand, we may want to make the switch to incident response much faster. Adding IDS signatures to detect this username if ever it appears may be a good solution: ::

 alert smb any any -> $HOME_NET any (msg:"pandabear"; smb.ntlmssp_user; content:"pandabear"; ...
 alert krb5 any any -> $HOME_NET any (msg:"pandabear"; krb5.cname; content:"pandabear"; ...

Please note that the first signature will require Suricata 7.0 and that dataset is a far better way to match IOCs with Suricata signatures.

To summarize this example, because Suricata is both an IDS and an NSM, there are multiple complementary approach options when threat hunting with Suricata.


Correlation using flow_id
-------------------------

Suricata performs flow tracking over most TCP/IP protocols. In the case of TCP, this is a direct mapping of flows to TCP sessions. For UDP, this is completed by looking at the IP information (source IP, port and destincation IP, and port) and applying a timeout logic. 

So a flow tracks what is happening during a communication between a client and a server:

.. index:: flow_id

All IP events contain a 'flow_id' key that is the same for all events in a single flow. This allows a user to to group all events.  

An example seen in jq on a simple HTTP request. You can also see here that jq is used to reformat the events: ::

  jq 'select(.flow_id==1541199918082444)|{"time": .timestamp, "type": .event_type, "src_ip":.src_ip, "src_port": .src_port, "dest_ip": .dest_ip, "dest_port": .dest_port}' -c eve.json
  {"time":"2017-07-24T15:54:12.716673+0200","type":"http","src_ip":"10.7.24.101","src_port":49163,"dest_ip":"216.239.38.21","dest_port":80}
  {"time":"2017-07-24T15:56:28.177134+0200","type":"fileinfo","src_ip":"216.239.38.21","src_port":80,"dest_ip":"10.7.24.101","dest_port":49163}
  {"time":"2017-07-24T16:15:05.777324+0200","type":"flow","src_ip":"10.7.24.101","src_port":49163,"dest_ip":"216.239.38.21","dest_port":80

We have three events here:

 - an HTPP request
 - a file information event (analysis of the data of the transferred file)
 - a flow entry containing the packets and bytes accounting as well as the duration of the flow

The flow event is generated once the flow is timed out by Suricata.

Some flows can have a lot more events if the protocol (like SMB) is doing a lot of transactions on a single flow.
 

Learning datasets
-----------------

At first look, the `dataset <https://suricata.readthedocs.io/en/latest/rules/datasets.html>`_ feature belongs to the IDS world (see :ref:`dataset-ioc` for example) as it provides matching on a list of elements. But 'dataset' can be enriched from the packet path, meaning it can be used to store the never-before-seen metadata.

For example, to collect all internal HTTP user agents: ::

  alert $HOME_NET any -> any any (msg:"new agent"; http.user_agent; \\
    dataset:isset,http-ua,type string, state /var/lib/http-ua.lst; \\

Every time Suricata will detect an HTTP user agent that has never been seen on the network by Suricata, it will trigger an alert. These events can be used to build a list of previously unseen items for all the fields that can be matched with a sticky buffer.

In our signature, the file '/var/list/http-ua.lst' is used to store the state. Suricata will dump the contents of the list it built into memory to the file (in our case, as a base64 string). This ensures that no new events will be generated if Suricata is forced to restart.
