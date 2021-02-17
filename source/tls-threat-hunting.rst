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

Before TLS 1.3, the X509 certificate is in clear text but in TLS 1.3, it is encrypted.

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
which means that the certificate can serve any site that matches ``*.gstatic.com``.

TLS JA3
-------


TLS JA3s
--------

Hunting on TLS events
=====================

Self signed certificate
-----------------------

Unsecure protocol
-----------------

Writing Suricata signatures on TLS
==================================
