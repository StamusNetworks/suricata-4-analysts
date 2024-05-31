================================
DNS detection and threat hunting
================================

Introduction
============

DNS is everywhere, as its main feature of resolving host names to IP addresses is mandatory for almost all Internet traffic.
DNS protocol, however, is doing far more than that and interesting analysis can be done on some specific requests.

In most environments, DNS requests are relayed through the internal DNS servers. This property makes it really interesting
for exfiltration of data or tunnelling.

One last thing to mention on DNS: it just shows an attempt. A DNS request to a domain proves that the domain was known and that a request has happened. Potentially, it was reached later. For example, the request was just a check or was otherwise triggered by the prefetch function of the browser that triggers a resolution of domain on a page even if the user is not clicking on it.


Protocol overview
=================

In DNS protocol, the client requests a DNS server that is defined in its configuration to request information about a resource.
If the server is responsible (authoritative) for the resource attached to the request, it will answer directly to the client.
If the resource is not local then the DNS server will query a higher level DNS server that will have the answer or will query another even higher level server. This hierarchical approach and proxy by default behavior is really peculiar to this protocol and has some consequences.

If the capture point of the traffic is before the internet gateway, there is a high chance that the DNS traffic will come from an internal server. For example, in a Microsoft environment the Active Directory often serves as the first level DNS server for the computer in the domain. This is a problem with regards to the visibility as the real client IP address will be hidden behind the intermediate server.

DNS requests have multiple types. The most common ones are:

 - A: request the IPv4 address associated with a host name
 - AAAA: request the IPv6 address associated with a host name
 - MX: request the SMTP servers serving a domain name
 - SRV: ask for the service for a specific application and domain
 - TXT: the record is mostly used to provide key value pair for check perspective such as domain ownership

One request can have multiple answers. For example, if we ask the SMTP server for the domain `stamus-networks.com`
we have:

.. code-block::

   $ host -t MX stamus-networks.com
   stamus-networks.com mail is handled by 1 aspmx.l.google.com.
   stamus-networks.com mail is handled by 5 alt1.aspmx.l.google.com.
   stamus-networks.com mail is handled by 5 alt2.aspmx.l.google.com.
   stamus-networks.com mail is handled by 10 alt3.aspmx.l.google.com.
   stamus-networks.com mail is handled by 10 alt4.aspmx.l.google.com.

This definitely makes sense for SMTP servers as it allows for the definition of a hierarchy of servers and fail over.

But this is also true for a simple IPv4 request:

.. code-block::

    host -t A google.com
    google.com has address 142.250.147.113
    google.com has address 142.250.147.102
    google.com has address 142.250.147.101
    google.com has address 142.250.147.138
    google.com has address 142.250.147.139
    google.com has address 142.250.147.100

This potential asymmetry between request size and answer paired with the fact that request are done over UDP is used
in a `DNS amplification attack <https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks>`_ where DNS
requests are sent with spoofed IP addresses (the victim address) that receives all the queried answers from the DNS servers. 

DNS analysis in Suricata
========================

Suricata has extensive support of DNS protocol over TCP and UDP.

DNS request and reponse are logged in separate events.

The following event is a query because the `dns.type` value is `query` and the
query is an `A` (value of `dns.rrtype`) request to resolve the hostname
`germakhya.xyz` (value of `dns.rrname`):

.. code-block:: JSON

  {
  "timestamp": "2019-07-05T22:10:33.164698+0200",
  "flow_id": 425899832864145,
  "event_type": "dns",
  "src_ip": "10.7.5.101",
  "src_port": 50643,
  "dest_ip": "10.7.5.5",
  "dest_port": 53,
  "proto": "UDP",
  "dns": {
    "type": "query",
    "id": 62832,
    "rrname": "germakhya.xyz",
    "rrtype": "A",
    "tx_id": 0,
    "opcode": 0
    }
  }

The answer to the previous request is seen in the event below. `dns.type` is set to
`answer` and we can see that the `dns.id` field that stores the id of the DNS exchange
is set to the same number `62832`.

.. code-block:: JSON

  {
    "timestamp": "2019-07-05T22:10:33.369515+0200",
    "flow_id": 425899832864145,
    "event_type": "dns",
    "src_ip": "10.7.5.101",
    "src_port": 50643,
    "dest_ip": "10.7.5.5",
    "dest_port": 53,
    "proto": "UDP",
    "dns": {
      "version": 2,
      "type": "answer",
      "id": 62832,
      "flags": "8180",
      "qr": true,
      "rd": true,
      "ra": true,
      "opcode": 0,
      "rrname": "germakhya.xyz",
      "rrtype": "A",
      "rcode": "NOERROR",
      "answers": [
        {
          "rrname": "germakhya.xyz",
          "rrtype": "A",
          "ttl": 599,
          "rdata": "95.142.46.236"
        }
      ],
      "grouped": {
        "A": [
          "95.142.46.236"
        ]
      }
    }
  }

Two types of outputs containing the reply information are available and can be combined in answer events based on the configuration.
`answers` displays the answers to the query with all parameters and the `grouped` output
contains a list of values for every type of answers returned by the server.

DNS and detection
=================

DNS keywords
------------

As of Suricata 7 there are two keywords dedicated to DNS: `dns.query` and `dns.opcode`.

`dns.query` is a sticky buffer checking the request value that is stored in the query event in the `dns.rrname` field.
It can be used to match on DNS resolution and is therefore very useful to detect Indicators of Compromise (IoCs) in
the traffic.

It worth mentioning that a DNS request to a domain does not indicate a connection to a domain but rather
the proximity to this domain. Techniques such as browser prefetch can trigger DNS resolution on hostnames that
are not visited but are present on a visited page. Additionally, DNS requests from security analysts checking
attacks must also be mentioned.

The DNS opcode matches the opcode that contains the type of operations. The most significant
are:

  - Query (0) for regular request/answer operation (see `RFC1035 <https://www.rfc-editor.org/rfc/rfc1035.html>`_)
  - Notify (4) for notification about a zone change (see `RFC1996 <https://www.rfc-editor.org/rfc/rfc1996.html>`_)
  - Update (5) for DNS Zone update operation (see `RFC2136 <https://www.rfc-editor.org/rfc/rfc2136.html>`_)
  - DNS Stateful Operations (DSO) defined a protocol update for persistent stateful sessions (see `RFC8490 <https://www.rfc-editor.org/rfc/rfc8490.html>`_)

If opcode 0 just indicates a regular exchange, the events with opcode 5 contain information about the update of zones and can
indicate interesting changes in the infrastructure.

Cookbook
--------

Match on a domain and its subdomains
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For instance, if the domain `germakhya.xyz` and all its subdomains are considered at risk, a signature
can be constructed over the following match:

.. code-block::

    dns.query; dotprefix; content:".germakhya.xyz"; endswith;

See :ref:`HTTP match on subdomains <match subdomains>` for explanations on usage of `endswith` and `dotprefix` keywords.

Hunting on DNS events
=====================

SRV requests and infrastructure discovery
-----------------------------------------

The request of type `SRV` are defined in `RFC2782 <https://www.rfc-editor.org/rfc/rfc2782.html>`_ and allows
users of the network to discover services. The following request is an example of SRV request where the client
asks the service for `_ldap._tcp.pdc._msdcs.fashionkings.com` (in field `dns.rrname`).

.. code-block:: JSON

  "timestamp": "2022-10-31T16:59:49.846977+0100",
  "flow_id": 1667414482265188,
  "event_type": "dns",
  "src_ip": "172.16.0.153",
  "src_port": 56559,
  "dest_ip": "172.16.0.12",
  "dest_port": 53,
  "proto": "UDP",
  "dns": {
    "type": "query",
    "id": 3038,
    "rrname": "_ldap._tcp.pdc._msdcs.fashionkings.com",
    "rrtype": "SRV",
    "tx_id": 0,
    "opcode": 0
  }

The construct of the requested service is interesting at it contains a lot of information:

 - `_ldap._tcp` is the service from an application point of view
 - `fashionkings.com` is the domain name.
 - `_msdcs` indicates a domain controler query
 - `pdc` is used to request the primary domain controler

See `Microsoft documentation on DNS-Based Discovery <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7fcdce70-5205-44d6-9c3a-260e616a2f04>`_

By consequence, the answer to this query will contain interesting information about the infrastructure:

.. code-block:: JSON

  "timestamp": "2022-10-31T16:59:49.847375+0100",
  "flow_id": 1667414482265188,
  "event_type": "dns",
  "src_ip": "172.16.0.153",
  "src_port": 56559,
  "dest_ip": "172.16.0.12",
  "dest_port": 53,
  "proto": "UDP",
  "dns": {
    "version": 2,
    "type": "answer",
    "id": 3038,
    "flags": "8580",
    "opcode": 0,
    "rrname": "_ldap._tcp.pdc._msdcs.fashionkings.com",
    "rrtype": "SRV",
    "rcode": "NOERROR",
    "answers": [
      {
        "rrname": "_ldap._tcp.pdc._msdcs.fashionkings.com",
        "rrtype": "SRV",
        "ttl": 600,
        "srv": {
          "priority": 0,
          "weight": 100,
          "port": 389,
          "name": "fashionkings-dc.fashionkings.com"
        }
      }
    ],

Here we discover that the primary domain controler for the domain `fashionkings` is the host `fashionkings-dc.fashionkings.com` (field `dns.answers[0].name`)
and that it runs as expected on port 389 (field `dns.answers[0].port`).

Finding guests on the network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The SRV requests can also be used to discover guests on the network. When a computer starts, it will try to connect
to its configured Windows domain and to do that it will use DNS discovery. As a result, it will emit a DNS request
that will contain a `dns.rrname` that will not be directed to the organization domain. The part after `_msdcs` will
be the domain name the system is registered too.

This is usually a good technique to spot an unexpected laptop in a network.

DNS update
----------

Detecting DNS update can be useful to spot unwanted behavior. This can
be done in Splunk with the following query:

.. code-block::

  event_type="dns" dns.opcode=5 | top src_ip, dest_ip

This will give the list of peers where updates are taking place. As of version 7, Suricata does not have a complete
parsing of the update messages so information obtained in the corresponding events will be poor.

DNS tunneling detection
-----------------------

Most common DNS tunneling solutions use the `TXT` to transmit the data. They can
be detected by statistical analysis. A simple stats query in Splunk could be a good
hunt start:

.. code-block::

  event_type="dns" dns.rrtype="TXT"" | stats count by src_ip

This query will output the IP addresses of the host that have done the most TXT requests
in the network. If some high counts are reached (like thousands of requests) over a short period (like
an hour) this may indicate that a DNS tunnel is active.

One enhancement of the previous approach is to use the average size of the dns event as
a complementary selector. To send data via the tunnel, one of the protocol fields needs to 
be used and as a result the size of the event should be higher than the norm. 

The following Splunk request gets all DNS queries and computes the size
of the event, then get statistics:

.. code-block::

  event_type="dns" dns.type="query" | eval esize=len(_raw)
    | stats count, avg(esize) by src_ip | sort -count

In the array below we can see that the first IP (which has
a DNS tunnel in place) exhibits vastly different numbers than
a regular host (second entry).

+--------------+-------+---------+
| IP address   | Count | Avg Size|
+==============+=======+=========+
| 192.168.3.1  | 18939 | 1414.44 |
+--------------+-------+---------+
| 172.16.1.152 | 150   | 574.28  |
+--------------+-------+---------+
