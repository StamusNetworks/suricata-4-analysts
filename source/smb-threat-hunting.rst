=================================
SMB detection and threat hunting
=================================

Introduction
============

SMB (Server Message Block) is a client-server communication protocol that has many implementations and is used primarily for sharing access to files printers and resources on the network. The Microsoft windows networks variant is known as Microsoft SMB Protocol. Other systems and OS types like Linux and Mac also include support for SMB.

There are many versions and history revisions

- SMB 1.0
- CIFS
- SMB 2.0
- SMB 2.1
- SMB 3.0
- SMB 3.0.2
- SMB 3.1.1

and third party implementations

- Samba
- Netsmb
- NQ
- MoSMB
- Fusion File Share by Tuxera
- Likewise


The implementation and the central internal usage of the protocol by many types of OSes makes it an ideal medium to be used by threat actors for internal/lateral movement. Once foothold is established , the actor can utilize build in and default available functionalities.


Protocol overview
=================

SMB Protocol functionality can also include the following

- Dialect negotiation
- Determining other Microsoft SMB Protocol servers on the network, or network browsing
- Printing over a network
- File, directory, and share access authentication
- File and record locking
- File and directory change notification
- Extended file attribute handling
- Unicode support

which makes it even more interesting and potent in terms of network visibility and monitoring.

SMB analysis in Suricata
=========================

Suricata supports protocol analysis and logging of all SMB versions like SMB 1.x, SMB 2.x and SMB 3.x.
Since Suricata 6, SMB has been further improved including thanks to community feedback and code donation.

.. code-block:: JSON

  {
    "timestamp": "2022-05-04T18:51:26.052278+0300",
    "flow_id": 1941808952834204,
    "pcap_cnt": 1189,
    "event_type": "smb",
    "src_ip": "10.136.0.69",
    "src_port": 49622,
    "dest_ip": "10.136.0.64",
    "dest_port": 445,
    "proto": "TCP",
    "pkt_src": "wire/pcap",
    "metadata": {
      "flowbits": [
        "ET.smbdcerpc.endians"
      ]
    },
    "smb": {
      "id": 85,
      "dialect": "3.11",
      "command": "SMB2_COMMAND_CREATE",
      "status": "STATUS_SUCCESS",
      "status_code": "0x0",
      "session_id": 52777564766265,
      "tree_id": 9,
      "filename": "PSEXESVC.exe",
      "disposition": "FILE_OPEN",
      "access": "normal",
      "created": 1651679428,
      "accessed": 1651679428,
      "modified": 1651679428,
      "changed": 1651679428,
      "size": 383872,
      "fuid": "000002a0-000c-0000-0021-00000000000c"
    }
  }

The ``smb`` object contains all the information about the specific SMB transaction. The ``smb`` object can be found in both ``"event_type":"alert"`` as supplemental metadata and as a stand alone SMB protocol log (``"event_type":"smb"``). It has detailed ``key:value`` field pairs giving information about the transaction. In the example above, ``filename`` is the name of the file accessed or transferred, ``disposition`` is instructing the action the server must take if the file already exists, ``command`` is containing the actual SMB command, ``status`` has the return status of the command.

.. code-block:: JSON

  "smb": {
    "id": 3,
    "dialect": "3.11",
    "command": "SMB2_COMMAND_SESSION_SETUP",
    "status": "STATUS_SUCCESS",
    "status_code": "0x0",
    "session_id": 52777564766265,
    "tree_id": 0,
    "ntlmssp": {
      "domain": "STCONSULT",
      "user": "Administrator",
      "host": "PC1"
    }

Other useful information is also available depending on the different SMB transaction or request. In the example above we have information about a session setup with details about ``domain`` - the domain , ``user`` - the user establishing the session,  and the ``host`` it is established from.

.. code-block:: JSON

  "smb": {
    "id": 73,
    "dialect": "3.11",
    "command": "SMB2_COMMAND_WRITE",
    "status": "STATUS_SUCCESS",
    "status_code": "0x0",
    "session_id": 52777564766265,
    "tree_id": 1,
    "dcerpc": {
      "request": "BIND",
      "response": "BINDACK",
      "interfaces": [
        {
          "uuid": "367abb81-9844-35f1-ad32-98f038001003",
          "version": "2.0",
          "ack_result": 0,
          "ack_reason": 0
        },
        {
          "uuid": "367abb81-9844-35f1-ad32-98f038001003",
          "version": "2.0",
          "ack_result": 3,
          "ack_reason": 0
        }
      ],
      "call_id": 2
    }

We can also count on Suricata to give us any specific data on top of SMB , like DCERPC and specific Microsoft protocol UUID (``uuid`` key).

SMB and detection
==================

SMB keywords
-------------

Out of the box Suricata supports the following keywords in alerts for matching inside the SMB transactions, all are sticky buffers:

- dcerpc.iface: Match on the UUID of the protocol
- dcerpc.opnum: Match on the opnum of the protocol
- dcerpc.stub_data: Match on the stub data (data/arguments of the remote call)
- smb.named_pipe: Match on SMB named pipe in tree connect
- smb.share: Match on SMB share name in tree connect

These keywords can be used in rules matching. It is important to note that those keywords are separate from the protocol fields matching that can further be used in SIEM queries of the SMB protocol logs produced by Suricata.


Hunting on SMB events
======================

SMB Scheduled task created remotely
-----------------------------------

Hunting on SMB events is a big task and to be more potent and successful it also needs infrastructure and organisational local knowledge.
As an example it might be interesting to know, highlight and investigate when a ``Scheduled Task`` is created remotely. This is indeed a task
that is definitely only done by some advanced system administrators and by some attackers.

For that we can use the following rule:

.. code-block::

  alert smb any any -> any any ( \\
     msg: "SN MS Scheduled task created remotely"; \\
     flow: to_server, established; \\
     dcerpc.iface:378E52B0-C0A9-11CF-822D-00AA0051E40F; dcerpc.opnum:0; \\
     reference:url,https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/4d44c426-fad2-4cc7-9677-bfcd235dca33; \\
     metadata:created_at 2022_09_20, updated_at 2022_09_20; \\
     target:dest_ip; \\
     sid:1000001; rev:1;)

The resulting alert event log could look like so, please note the ``flow`` and ``smb`` subsections of the alert event:

.. code-block:: JSON

  {
    "stream": 1,
    "ether": {
      "dest_mac": "ff:ff:ff:28:fe:2d",
      "src_mac": "ff:ff:ff:7a:71:40"
    },
    "timestamp": "2022-09-27T20:04:27.911458+0200",
    "dest_ip": "10.10.11.15",
    "tx_id": 9,
    "packet_info": {
      "linktype": 1
    },
    "flow_id": 1056255386940814,
    "flow": {
      "dest_ip": "10.10.11.15",
      "src_ip": "10.10.22.55",
      "pkts_toserver": 17,
      "pkts_toclient": 15,
      "bytes_toserver": 3983,
      "bytes_toclient": 3240,
      "start": "2022-09-27T20:04:27.311464+0200",
      "src_port": 55067,
      "dest_port": 445
    },
    "type": "json-log",
    "in_iface": "eth0",
    "app_proto": "smb",
    "metadata": {
      "flowbits": [
        "ET.smbdcerpc.endians"
      ]
    },
    "src_ip": "10.10.22.55",
    "alert": {
      "metadata": {
        "created_at": [
          "2022_09_20"
        ],
        "updated_at": [
          "2022_09_20"
        ]
      },
      "rev": 1,
      "source": {
        "port": 55067,
        "ip": "10.10.22.55"
      },
      "action": "allowed",
      "gid": 1,
      "category": "",
      "severity": 3,
      "target": {
        "port": 445,
        "ip": "10.10.11.15"
      },
      "signature_id": 1000001,
      "lateral": "intranet",
      "signature": "SN MS Scheduled task created remotely"
    },
    "event_type": "alert",
    "@version": "1",
    "input": {
      "type": "log"
    },
    "dest_port": 445,
    "@timestamp": "2022-09-27T18:04:27.911Z",
    "proto": "TCP",
    "src_port": 55067,
    "smb": {
      "id": 10,
      "tree_id": 1,
      "session_id": 17607151321153,
      "dialect": "3.11",
      "dcerpc": {
        "response": "UNREPLIED",
        "request": "REQUEST",
        "req": {
          "stub_data_size": 264,
          "frag_cnt": 1
        },
        "call_id": 2,
        "opnum": 0
      },
      "command": "SMB2_COMMAND_IOCTL",
      "status": "STATUS_PENDING",
      "status_code": "0x103"
    }
  }

SMB Status Access Denied
------------------------

Access denied in SMB could be common occurrences in cases when creating or connecting to a shared directory via the tree connect operation:

.. code-block:: JSON

  {
    "timestamp": "2022-05-20T20:31:58.553243+0200",
    "flow_id": 1047258484058895,
    "event_type": "smb",
    "src_ip": "10.150.1.93",
    "src_port": 52092,
    "dest_ip": "10.150.1.46",
    "dest_port": 445,
    "proto": "TCP",
    "pkt_src": "wire/pcap",
    "metadata": {
      "flowbits": [
        "ET.smbdcerpc.endians",
        "ET.dcerpc.mssrvs",
        "ET.smb.binary"
      ]
    },
    "smb": {
      "id": 54,
      "dialect": "3.11",
      "command": "SMB2_COMMAND_TREE_CONNECT",
      "status": "STATUS_ACCESS_DENIED",
      "status_code": "0xc0000022",
      "session_id": 30786459795473,
      "tree_id": 0,
      "share": "\\\\WZVCDYTZUR6.GONE.LOCAL\\C$",
      "share_type": "UNKNOWN"
    }
  }

However what could be interesting is to use the SMB protocol and flow transaction data in Suricata to detect brute forcing. The idea is to highlight all SMB flows that have many ``STATUS_ACCESS_DENIED`` command results in the same flow indicating possible brute forcing.

This could be achieved by combining 2 Suricata log fields. Mainly ``flow_id`` and ``smb.status``. We can use that combination as ``flow_id`` contains the Suricata native unique flow identifier which can be used to correlate events such as alerts, flows, file transactions and protocol logs from the same flow.

JQ command line query
~~~~~~~~~~~~~~~~~~~~~

.. code-block::

  jq 'select(.event_type=="smb" and .smb.status == "STATUS_ACCESS_DENIED")|.flow_id' /var/log/suricata/eve.json | sort | uniq -c
  10 1047258484058895

The JQ query above returns the result which is 10 time status ``STATUS_ACCESS_DENIED`` in the flow whose ``flow_id`` is ``1047258484058895``.
So we have 10 Access denied in the same flow which is definitely suspicious.

Kibana query
~~~~~~~~~~~~

Create a table visualisation that uses an aggregation in Kibana on the field ``flow_id`` with the following query search

.. code-block::

  event_type:"smb" AND smb.status:"STATUS_ACCESS_DENIED"

Splunk query
~~~~~~~~~~~~

Similar for Splunk the query can be:

.. code-block::

  event_type=smb sourcetype="suricata:smb" smb.status=STATUS_ACCESS_DENIED |
      table src_ip, dest_ip, flow_id |
      stats count by src_ip,dest_ip,flow_id |
      sort - count
