=================================
HTTP detection and threat hunting
=================================

Introduction
============

HTTP is running the world. It is used by human's actions or, in the case of HTTPS protocol, directly or below TLS.
It is also widely used by systems via REST API and other inter-server communications.

One of the great benifits of HTTP is the weak message structure which makes it easy to develop a client.
It is a loose text-based protocol and as such looks very similar to free text. This makes it highly adaptable, but from
a security point of view this complicates things. Hunting something that has multiple forms can be rather complex. 


Protocol overview
=================

In HTTP, the client is the first to send data via an HTTP request. This message contains headers with
a few mandatory fields and a lot of optional headers which give more context to the server about the request
so it can adapt its answer. The request contains an optional body.
The server responds with an answer that has the same structure with headers and a body. This is because HTTP is focused on getting
information from the server.

To see an example of the minimum requirements of a request is, let's look at this minimal request to google
done via netcat where we ask for the home page ``/`` with protocol version ``1.1``:

.. code-block::

  # nc -v google.fr 80
  GET / HTTP/1.1

This is the answer from Google:

.. code-block::

  HTTP/1.1 200 OK
  Date: Sun, 25 Sep 2022 21:17:08 GMT
  Expires: -1
  Cache-Control: private, max-age=0
  Content-Type: text/html; charset=ISO-8859-1
  Server: gws
  X-XSS-Protection: 0
  X-Frame-Options: SAMEORIGIN
  Set-Cookie: AEC=AakniGO859M8HPupnneVpexM15eeWdGOBL_LX5TGiy5GsqI_Fnm0F8UEIg; expires=Fri, 24-Mar-2023 21:17:08 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax
  Accept-Ranges: none
  Vary: Accept-Encoding
  Transfer-Encoding: chunked

  5acf
  <!doctype html><html itemscope="" itemtype="http://schema.org/WebPage" ...

This answer has the typical structure of an HTTP message with status line (here ``HTTP/1.1 200 OK``), followed by the headers (key and value),
then an empty line that is followed by the body.

This dissymmetry between the request and the response in this example emphasizes one of the main concepts of HTTP design: it should work even if client implementation is really poor.

If we look at the same HTTP request to google.fr done via Firefox, we have the following request:

.. code-block::

  GET / HTTP/1.1
  Host: google.fr
  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
  Accept-Language: en-US,en;q=0.5
  Accept-Encoding: gzip, deflate
  Connection: keep-alive
  Upgrade-Insecure-Requests: 1

The headers list is far longer and gives more information about what the client
is able to support or what it wants from the server's answer. For example, here, because
we have the header ``Upgrade-Insecure-Requests`` set to 1, we don't get the web page
content as we got in the previous request but we have a redirection to the Secure
HTTPS version of google.fr:

.. code-block::

  HTTP/1.1 301 Moved Permanently
  Location: http://www.google.fr/
  Content-Type: text/html; charset=UTF-8
  Date: Sun, 25 Sep 2022 21:33:01 GMT
  Expires: Tue, 25 Oct 2022 21:33:01 GMT
  Cache-Control: public, max-age=2592000
  Server: gws
  Content-Length: 218
  X-XSS-Protection: 0
  X-Frame-Options: SAMEORIGIN

As we will see later, the fact that a lot of freedom is given in the protocol
is a key point in profiling non-regular behavior that does not follow the implicit norm. 


HTTP analysis in Suricata
=========================

Suricata has very robust support for HTTP. The development of the parser was initiated at the beginning of the project
and has continued to evolve with continuing update releases.

HTTP request and response are logged in a single event:

.. code-block:: JSON

  {
    "timestamp": "2019-07-05T22:06:30.877497+0200",
    "flow_id": 1831154258612572,
    "pcap_cnt": 47339,
    "event_type": "http",
    "src_ip": "10.7.5.5",
    "src_port": 62152,
    "dest_ip": "198.12.71.157",
    "dest_port": 443,
    "proto": "TCP",
    "pkt_src": "wire/pcap",
    "tx_id": 0,
    "http": {
      "hostname": "198.12.71.157",
      "http_port": 443,
      "url": "/login/process.php",
      "http_user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
      "http_content_type": "text/html",
      "http_method": "GET",
      "protocol": "HTTP/1.1",
      "status": 200,
      "length": 173
    }
  }

The ``http`` object contains all the information about the request and the response. Fields like ``hostname`` or
``http_user_agent`` are coming from the client and fields such as ``status``, ``length``, or ``http_content_type``
are coming from the server. The log also include the ``tx_id`` which stands for transaction identifier. It is
giving the number of HTTP transaction (request + response) seen on the flow at the moment of the request.
In this example it is 0, which means this is the first one.

As you can see, the event shown here does not contain all the headers. The dump of all headers can be activated
in the configuration via the ``dump-all-headers`` configuration in the HTTP logging. This will provide far more
information, but it is also going to be far more verbose:

.. code-block:: JSON

    "request_headers": [
      {
        "name": "Cookie",
        "value": "session=okmKYUc4i80CZ2Rflxy91qtVJoI="
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
      },
      {
        "name": "Host",
        "value": "198.12.71.157:443"
      },
      {
        "name": "Connection",
        "value": "Keep-Alive"
      }
    ],
    "response_headers": [
      {
        "name": "Content-Type",
        "value": "text/html; charset=utf-8"
      },
      {
        "name": "Content-Length",
        "value": "173"
      },
      {
        "name": "Cache-Control",
        "value": "no-cache, no-store, must-revalidate"
      },
      {
        "name": "Pragma",
        "value": "no-cache"
      },
      {
        "name": "Expires",
        "value": "0"
      },
      {
        "name": "Server",
        "value": "Microsoft-IIS/7.5"
      },
      {
        "name": "Date",
        "value": "Fri, 05 Jul 2019 20:06:30 GMT"
      }
    ]

Another interesting feature of HTTP support in Suricata is the transparent decompression of the HTTP response body.
If the client supports the feature, the server can return the object asked for by the client in a compressed form
to downsize the transfer. The result is that the content of the HTTP body in the TCP stream is just compression noise.
Suricata decompresses the data in real-time and provides the decompressed content to the keyword and layers that are using
the HTTP response body.

The HTTP response body can be logged in alerts and this greatly improves the context provided as the stream TCP cannot be read by
a human.

.. note::

  Check the `eve HTTP format <https://suricata.readthedocs.io/en/latest/output/eve/eve-json-format.html?highlight=http#event-type-http>`_ page in Suricata manual for more information on the HTTP events.

Suricata supports file extraction over HTTP, so any of the techniques and information of :ref:`File Analysis <file-analysis>` chapter
apply here.

HTTP and detection
==================

HTTP keywords
-------------

Suricata has a more than 25 sticky buffer keywords to match on HTTP fields, covering
most of the headers and the content. These last ones are interesting, specifically 
``http.response_body`` that matches on the body of the response sent by the server. As
described in the previous chapter, the content sent by the server can be on a compressed
form and Suricata will provide the decompressed version to the detection engine.

Most keywords match on a normalized field. This is really convenient as the
rules writer does not have to take the possible variant into account. For example,
the ``http.host`` keyword is normalized and will always be lowercase. This prevents
trivial evasion of detection by connecting to `BaDdoMAin.OrG` instead of the regular
`baddomain.org`.

In some cases, the characteristic seen in the traffic is dependant of the
content seen on the wire. For this reason, Suricata is providing some alternate
keywords to match on the raw, unnormalized content. For example, ``http.host.raw``
will match on the HTTP host in its raw form.

Cookbook
--------

Match on a domain and its subdomains
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A domain is known to be malicious and we want to alert on all requests to this domain
or any of its subdomains:

.. code-block::

   alert http any any -> any any (msg:"Bad domain"; \\
        http.host; dotprefix; content:".pandabear.gov"; endswith;
        sid:1; rev:1;)

The match is obtained by using the sticky buffer ``http.host`` to
match on the HTTP host sent by the client. By using ``dotprefix``, a 
``.`` will be prepended to the buffer so it will not match on ``lovelypandabear.gov``.
Then the signature uses the ``endswith`` keyword to ensure the string ends with the specified content.
It will prevent a match on a domain like ``pandabear.governed.org``.


Checking malicious HTTP user agent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some variants of Trickbot are using an HTTP user agent that is set to ``test``.
A signature to detect this behavior could be:

.. code-block::

   alert http any any -> any any (msg:"Bad domain"; \\
        http.user_agent; content:"test"; startswith; endswith;
        sid:1; rev:1;)

We use the same technique as the domain with the ``endswith`` keyword
that we complement with ``startswith`` to ensure full equality
of the strings.

Clear text authentication and password extraction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Clear text authentication over HTTP is still relevant in some environments. 
Detecting this behavior and collecting the user and password to
check them against other systems to detect credential reuse is really
interesting. 

This can be done with a single signature:

.. code-block::

  alert http any any -> any any (msg:"HTTP unencrypted with password"; \\
       http.header; content:"Authorization|3a 20|Basic"; nocase; \\
       base64_decode:bytes 0, offset 1,relative; \\
       base64_data; pcre:"/([^:]+):(.+)/,flow:user,flow:password"; \\
       sid:1; rev:1;)

This signature first checks for the `Authorization` header and then uses
``base64_decode`` to convert the content from base64 to regular encoding.
The ``base64_data`` is a sticky buffer to access the content transformed
by ``base64_decode``. In this buffer, we have the user name followed
by the password so we can extract it via a regular expression using the ``pcre`` keyword.

The regular expression is really interesting as it uses the data extraction feature
of Suricata:

.. code-block::

  pcre:"/([^:]+):(.+)/,flow:user,flow:password"

The regular expression has 2 groups `([^:]+)` and `(.+)`. The first
one gets everything before the `:` and the second one take the rest.
So the first group retrieves the user and second extracts the password. The magic appends
in the modifiers: ``,flow:user,flow:password``. This is a Suricata extension.
It is stating here that the first group should be stored in a flow variable named
``user`` and that second group should be stored in a flow variable named ``password``.

Doing this, the alert is augmented with a ``metadata`` object that contains a ``flowvars``
with the extracted values as shown below:

.. code-block:: JSON

  {
    "timestamp": "2022-01-07T15:13:40.947137+0100",
    "flow_id": 206063044707455,
    "pcap_cnt": 69,
    "event_type": "alert",
    "src_ip": "192.10.0.1",
    "src_port": 58944,
    "dest_ip": "192.10.0.2",
    "dest_port": 80,
    "proto": "TCP",
    "metadata": {
      "flowvars": [
        {
          "user": "regit"
        },
        {
          "password": "ILoveSuri"
        }
      ]
    },


Hunting on HTTP events
======================

HTTP hunting signatures in ETOpen and ETPro
-------------------------------------------

This is not a technique to hunt directly using application layer events, but the `ETOpen and ETPro ruleset <https://www.proofpoint.com/us/resources/data-sheets/etpro-versus-et-open-ruleset-comparison>`_ 
contains a few hundred particularly interesting hunting signatures for the HTTP protocol. Enabling these
signatures and considering them as pre-executed queries is highly recommended.

For example, the following signature matches on POST request using an IPv4 address as hostname and missing
headers that are usually sent by regular browsers.

.. code-block::

  alert http $HOME_NET any -> $EXTERNAL_NET any ( \\
        msg:"ET HUNTING GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 2"; \\
        flow:established,to_server; \\
        http.method; content:"POST";
        http.user_agent; content:"|20|Firefox/"; nocase; fast_pattern; \\
        http.host; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}/"; \\
        http.header_names; content:"|0d 0a|Host|0d 0a|"; depth:8; \\
           content:!"Accept-Encoding"; \\
           content:!"Referer"; \\
           content:!"X-Requested-With"; nocase; \\
        classtype:bad-unknown; sid:2018359; rev:4; \\
        metadata:created_at 2014_04_04, former_category INFO, updated_at 2020_08_20;)

This signature is interesting because it matches the Tactics, Techniques, and Procedures of
some actors without having to know the threat.


Rare HTTP user agents
---------------------

As HTTP is frequently seen on network, using the rare approach is often a good way to see outliers
that can be interesting to investigate.

This can be done in Splunk via the following query:

.. code-block::

  search event_type="http" | rare http.http_user_agent | sort count | head 10


Rare HTTP hosts queried without referrer
----------------------------------------

The list of hosts used as an entry point when browsing is fairly small in most environments.
Getting the rarest one is interesting because it will exhibit potential unwanted behavior such
as payload download.

This can be done in Splunk via the following query:

.. code-block::

  event_type="http" AND NOT http.http_refer=* | rare http.hostname | sort count


HTTP errors with Abnormal Content Length
----------------------------------------

Some attackers try to hide their exchange by pretending the requests are failing. As unfound pages are
usually fairly small, looking at error pages with a decent size is a good start for a hunt.


This can be done in Splunk via the following query:

.. code-block::

  event_type="http" http.status=4* http.length>=10000 |
      sort -http.length |
      table src_ip, dest_ip, http.hostname, http.status, http.url, http.length

Kibana users can use the following search using Lucene syntax:

.. code-block::

   event_type:http AND http.status:>400 AND http.status:<500 AND http.length:>10000
