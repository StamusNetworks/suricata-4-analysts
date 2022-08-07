Generic Threat Hunting
======================

flow_id correlation
-------------------

Suricata does flow tracking over most TCP/IP protocols. In the case
of TCP this is a  direct mapping of flows to TCP sessions. In the case of UDP,
this is done by looking at the IP information (source IP and port and 
destination IP and port) and applying a timeout logic.

So a flow tracks what is happening on a communication between a client and
a server.

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

Some flows can have much more events if the protocol (like SMB) is doing a lot of transactions
on a single flow.
 
