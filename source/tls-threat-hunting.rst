==================
TLS Threat Hunting
==================

Introduction
============

The TLS protocol is everywhere. The Secure Socket Layer implementation initially
developed for the Mozilla browser has evolved into one of the most prominent
standard. It is used massively on HTTPS and all over the place to encrypt communication.
Yes, encrypt, which for network security is equivalent to say hide all the juicy details.

But there is still information that can be extracted or built and this can be used for threat
hunting as well as for an IDS approach.

Protocol overview
=================

In all version of TLS, the client is opening a connection to the server and sends an initial message.
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


Hunting on TLS events
=====================

Self signed certificate
-----------------------

Unsecure protocol
-----------------

Writing Suricata signatures on TLS
==================================
