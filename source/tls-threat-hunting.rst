================================
TLS Detection and Threat Hunting
================================

Introduction
============

The TLS protocol is everywhere. The Secure Socket Layer implementation initially
developed for the Mozilla browser has evolved into one of the most prominent
standards. It is widely used in HTTPS and other communications protocols to encrypt communication.
Yes, encrypt, which for network security is equivalent to say hide all the juicy details.

But there is still information that can be extracted or built. This can be used for threat
hunting as well as for an IDS approach.

Protocol overview
=================

In all versions of TLS, the client is opening a connection to the server and sends an initial message.
It contains the client capabilities in term of encryption. Using that the server then replies with
potential agreement on encryption technique to use as well as its certificates. Client analyses this
message and check that the server certificate is valid. If everything is fine, client sends
its certificates and a seed needed to start the encrypted exchange. The server then initiate the encryption
and the session switch to encryption.

Before TLS 1.3, the X509 certificate was in clear text but since TLS 1.3, it is encrypted. As
a result visibility had been really limited with TLS 1.3.

In most implementation, there is a TCP connection and then a TLS handshake but in some cases
the server offers a clear text and an encrypted service on the same port. In this case, a
mechanism is needed on the clear text protocol to trigger the switch. In most implementation
this is the ``STARTTLS`` message. Most common protocol using this are SMTP, IMAP and FTP.

TLS analysis in Suricata
========================

TLS handshake analysis
----------------------

Suricata does not decrypt the traffic but realizes an analysis of the TLS handshake. By doing this it
manages to extract information on the TLS characteristics as well as on the X509 certificates.
This data are written in the ``tls`` event type and are also added to the ``alert`` when they are available.

Suricata can also extract the certificate chain sent by the server and store it inside the event or
as a separate file.

Extracted fields
----------------

Suricata extracts information about the TLS handshake and output this information in ``tls`` events.

A typical event is the following

.. code-block:: JSON

  {
    "timestamp": "2020-05-08T23:32:34.218590+0200",
    "flow_id": 1737090126716212,
    "pcap_cnt": 41441,
    "event_type": "tls",
    "src_ip": "10.0.0.128",
    "src_port": 52046,
    "dest_ip": "64.233.179.94",
    "dest_port": 443,
    "proto": "TCP",
    "tls": {
      "subject": "C=US, ST=California, L=Mountain View, O=Google LLC, CN=*.gstatic.com",
      "issuerdn": "C=US, O=Google Trust Services, CN=GTS CA 1O1",
      "serial": "74:E6:32:EA:F9:C6:35:C2:02:00:00:00:00:63:98:DD",
      "fingerprint": "f5:af:1c:45:74:1b:2e:f2:5a:85:d1:49:be:dc:97:0d:2e:0c:97:a2",
      "sni": "www.gstatic.com",
      "version": "TLS 1.2",
      "notbefore": "2020-04-15T20:24:10",
      "notafter": "2020-07-08T20:24:10"
    }
  }


Among the interesting fields, we have the ``tls.sni`` that stands for TLS Server Name Indication and is
in fact the host name requested by the client. This is sent by client in the first message to allow the server to choose which certificate to send in his answer. This way the server can honor multiple services on the same port.
For example, in this case, we have the ``tls.subject`` equals to ``"C=US, ST=California, L=Mountain View, O=Google LLC, CN=*.gstatic.com"``
which means because of the ``CN`` field that the certificate can serve any site that matches ``*.gstatic.com``. So we have some supplementary information thanks to the TLS SNI.

TLS JA3
-------

In a standard TLS handshake, really few is known about the client side. Usually client certificate is not used to it is not sent over the wire so really few is
known about the client.
If we compare with HTTP, we don't have the user agent field that (even if it is a declarative field) is a really valuable source of information
as it allows to identify and classify protocol clients.

`JA3 <https://github.com/salesforce/ja3>`_ was created by John B. Althouse, Jeff Atkinson and Josh Atkins (hence the name of the method) to address this issue. It is based on the fact
that common implementation will send in the initial message similar negotiation parameters. And by selecting carefully some of this parameters, we can build an identifier that discriminate
with a fine granularity the implementation. As most clever technique this looks really simple but it has proven to be an really efficient way to fingerprint TLS client.
Identifying malware traffic with JA3 has proven to be successful even if there is a non zero false positive.

The following example is a Suricata TLS event with JA3 activated.

.. code-block:: JSON

  {
    "timestamp": "2020-05-08T23:35:24.922820+0200",
    "flow_id": 995065818031171,
    "pcap_cnt": 51204,
    "event_type": "tls",
    "src_ip": "10.0.0.128",
    "src_port": 52047,
    "dest_ip": "144.91.76.208",
    "dest_port": 443,
    "proto": "TCP",
    "tls": {
      "subject": "C=GB, ST=London, L=London, O=Global Security, OU=IT Department, CN=example.com",
      "issuerdn": "C=GB, ST=London, L=London, O=Global Security, OU=IT Department, CN=example.com",
      "serial": "00:9C:FC:DA:1D:A4:70:87:5D",
      "fingerprint": "b8:18:2d:cb:c9:f8:1a:66:75:13:18:31:24:e0:92:35:42:ab:96:89",
      "version": "TLSv1",
      "notbefore": "2020-05-03T11:07:28",
      "notafter": "2021-05-03T11:07:28",
      "ja3": {
        "hash": "6734f37431670b3ab4292b8f60f29984",
        "string": "769,47-53-5-10-49171-49172-49161-49162-50-56-19-4,65281-10-11,23-24,0"
      },
      "ja3s": {
        "hash": "623de93db17d313345d7ea481e7443cf",
        "string": "769,49172,65281-11"
      }
    }
  }

The ja3 part is the following

.. code-block:: JSON

  {
    "ja3" {
      "hash": "6734f37431670b3ab4292b8f60f29984",
      "string": "769,47-53-5-10-49171-49172-49161-49162-50-56-19-4,65281-10-11,23-24,0"
    }
  }

It is composed of 2 fields, a string that is build by concatenating a predefined list of negotiation parameters and a hash value that is simply the md5 hash of the string.

And this hash has been linked to `Trickbot <https://twitter.com/4a4133/status/1043246635239854081?lang=en>`_ by John B. Althouse. So just using this information is enough
to identify a potential malware. And even if the server infrastructure is composed of multiple services and evolves, the JA3 of the client will stay the same as the
data are based on client first message that can not be influenced by the server.

TLS JA3s
--------

JA3s is almost enough to define what JA3s is. It is a technique similar to JA3 that is used to fingerprint the TLS implementation of server. By analysing
the first message of the server, a predefined list of parameters is concatenated and a md5 hash is built. This leads to the following result
in our previous entry:

.. code-block:: JSON

  {
    "ja3s": {
      "hash": "623de93db17d313345d7ea481e7443cf",
      "string": "769,49172,65281-11"
    }
  }

But there is a big difference between JA3 and JA3s. As the first message of the server is an answer to the client to continue the negotiation, the server message is dependant of the client.
As a result, the JA3s is in fact an identifier of a client and server connection more than a server identification. To be fully explicit, two different clients connecting to
a server will result in two different JA3s value.


TLS and Detection
=================

TLS keywords
------------

As usual, it is recommended to use all sticky buffers variant as they are offering more flexbility and better performance.

There is two classes of keywords, the one matching the TLS certificate information and the one matching on ja3 and ja3s data.

.. csv-table::
  :file: tls-keywords.csv
  :header-rows: 1

Extensive documentation and syntax explanation is available in Suricata documentation in the `TLS keywords page <https://suricata.readthedocs.io/en/latest/rules/tls-keywords.html>`_.

Cookbook
--------

Detecting expired certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Let's get an alert when one of the a server we monitor has an expired certificate

.. code-block::

  alert tls $SERVERS any -> any any (msg:"Expired certs on server"; \\
       tls_cert_expired; \\
       sid:1; rev:1;)

Here we simply use, the `tls_cert_expired` keyword and the `$SERVERS` variable that needs to be placed on the left as
the certificate data we want to check are coming from the servers.

Checking that internal PKI is used
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The company we work for is running an expensive PKI and we want to be sure it is used for all the services running on our servers.
If the TLS issuer of our PKI is `C=US, O=My Company`, we can simply use the following signature that leverage the `tls.cert_issuer`
sticky buffer keyword.

.. code-block::

  alert tls $SERVERS any -> any any (msg:"Non Company PKI on server"; \\
       tls.cert_issuer; content:!"C=US, O=My Company"; \\
       sid:2; rev:1;)

We use an `!` on the content keyword to negate the match.

If we need to deal with history we can just do trigger alert for certificate where the beginning of validity is after the date when
the PKI is supposed to be implemented everywhere:

.. code-block::

  alert tls $SERVERS any -> any any (msg:"Non Company PKI on server"; \\
       tls.cert_issuer; content:!"C=US, O=My Company"; \\
       tls_cert_notbefore:>2021-04-01; \\
       sid:2; rev:1;)


Checking Tactiques, Techniques and Procedure on certificate building
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Creating correctly TLS certificates is not the most trivial task and it is the same for attacker. For example,
some Ursnif campaign have been using certificates where the subject DN was of the form `C=XX, ST=1, L=1, O=1, OU=1, CN=*`. This `XX` and `1`
are not something expected in regular certificates and it is a mark of the (Tactiques Techniques an Procedures) TTP of the attacker.

This is something we can detect with a signature:

.. code-block::

  alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"Ursnif like certificate"; \\
       tls.cert_subject; content:"C=XX"; content:"=1,"; \\
       sid:3; rev:1;)

Here we alert when a certificate on an external server is using a certificate that follows the pattern we have found in the
Ursnif campaign.

Verifying a list of known bad JA3
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


.. code-block::

  alert tls $HOME_NET any -> any any (msg:"New internal certificate authority"; \\
        tls.ja3; dataset:set,bad-ja3, type string, load bad-ja3.lst; \\
        sid:4; rev:1;)


Here we alert as soon a TLS JA3 from the set of known bad JA3 is seen.


Build the list of internally used certificate authorities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In a production environment, it is useful to know what are the TLS certificates authorities
that are used internally. Suricata can be used to do so by using the dataset keyword:

.. code-block::

  alert tls $HOME_NET any -> any any (msg:"New internal certificate authority"; \\
        tls.issuerdn; dataset:set,internal-issuers, type string, state internal-issuers.lst, memcap 10Mb, hashsize 100; \\
        sid:5; rev:1;)

Here we alert as soon a TLS issuer is seen coming from the internal network and has never been seen before.

Hunting on TLS events
=====================

Self signed certificates
------------------------

Self signed certificates can be detected via signatures. See `this blog post <https://www.stamus-networks.com/blog/2015/07/24/finding-self-signed-tls-certificates-suricata-and-luajit-scripting>`_ by Stamus Networks explaining the process using a lua based
signature.

This can also be done using the TLS events. If `tls.issuerdn` is equal to `tls.subject` then we have a self signed certificate.

If you have only the EVE JSON file and access to the command line, you can use `jq` to find them ::

  cat eve.json | jq 'select(.event_type=="tls" and .tls.issuerdn==.tls.subject)'

In Splunk, one can simply do ::

 event_type="tls" tls.subjectdn=tls.issuerdn

If your data are in Elasticsearch you can do a search in Kibana:

Unsecure protocol
-----------------


