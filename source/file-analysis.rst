=============
File Analysis
=============

Introduction
============

As Suricata understands most major application layers, it is able to track
the file transfered over the wire. The list of application layers supporting 
file extraction includes:

 - HTTP
 - FTP
 - SMB
 - NFS
 - SMTP
 - HTTP2 

Interesting features are a consequence of this. First, it allows Suricata to generate
events containing information about the files. The :ref:`fileinfo events <fileinfo-events>` 
are generated once any tracked file transfer is over (independantly of any detection). These events contain details about
the file such as its name, various hashes of its content (sha1, sha256, ...) and identification
of the file type based on its content.
 
The second feature is the extraction of the file which is triggered by the `filestore <https://suricata.readthedocs.io/en/latest/rules/file-keywords.html?#filestore>`_ keyword in signature.
Extraction can also be switched on globally but it is really intensive in term of performance. One thing
to mention about extraction is that it is deduplicated as the storage of file on disk is done once per sha256.
file_data keyword

Third feature associated with file is the analysis of file content that can be done via the `file_data` keyword.
Signature can be written to match on the content of file which for example can be compressed in the case of HTTP
or under a base64 encoded form in the case of SMTP.

Please see, Suricata manual for how to set up `file extraction <https://suricata.readthedocs.io/en/latest/file-extraction/file-extraction.html>`_.

.. index:: Fileinfo event

.. _fileinfo-events:


Fileinfo events
===============

The structure of a `fileinfo` event is the following:

.. code-block:: JSON

  {
    "timestamp": "2019-07-05T22:01:04.745891+0200",
    "flow_id": 2209746386047329,
    "pcap_cnt": 33861,
    "event_type": "fileinfo",
    "src_ip": "5.188.168.49",
    "src_port": 80,
    "dest_ip": "10.7.5.101",
    "dest_port": 49686,
    "proto": "TCP",
    "community_id": "1:shQmhcocLIrJ1WtOAbgShXgB5FY=",
    "http": {
      "hostname": "5.188.168.49",
      "url": "/sin.png",
      "http_user_agent": "WinHTTP loader/1.0",
      "http_content_type": "image/png",
      "http_method": "GET",
      "protocol": "HTTP/1.1",
      "status": 200,
      "length": 110718
    },
    "app_proto": "http",
    "fileinfo": {
      "filename": "/sin.png",
      "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
      "gaps": false,
      "state": "CLOSED",
      "sha1": "2408c5380ddca2bbd53b87c27132b72f0927c70f",
      "sha256": "110743634989ed7a3293b2e39ad85c255fc131c752e029f78d37d4fb8c1dc7f6",
      "stored": false,
      "size": 369664,
      "tx_id": 1
    }
  }

The event contains a `fileinfo` object that contains the following fields:

 - `filename` announced by the servers
 - `magic` computed by analysing the beginning of the file
 - `size` getting us the file size

and it also contains a regular `http` as this file was capture on a HTTP flow. On a different
application layers different subobject would have been present. The field `app_proto` is a good
way to know which suboject will be present. 

This event is a good example of the value of the various mechanism in place in Suricata. The
HTTP parser told us that the file content type (`http.http_content_type`) announced by the
server is an `image\png`. This would be fine if the analysis of content of the file did not
find out (in the key `fileinfo.magic`) that the file is in reality an executable. For the reference, this
file was used in an infection by the Trickbot malware.

This can be confirmed by checking the sha1 or sha256 hash of the file in
`Virustotal <https://www.virustotal.com/gui/file/110743634989ed7a3293b2e39ad85c255fc131c752e029f78d37d4fb8c1dc7f6>`_.
This file is flagged as malicous by more than 50 security vendors and associated to Trickbot by some of them.

.. figure:: img/virustotal.png
  
   Information from Virustotal on the file.


Detection on file data
======================

file.data keywords
------------------

The `file.data` keyword matches on the content of the file, so it can be used to do an analysis of the content of the transferred file
with the inspection capability of Suricata. This keyword is aliased to `file_data` (which is used in a lot of available signatures as it
is the original name). `file.data` is a sticky buffer so it will trigger the matching on the file content for all subsequent match keywords.


Magic analysis
--------------




Threat hunting with file
========================


