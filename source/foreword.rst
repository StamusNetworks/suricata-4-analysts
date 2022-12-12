Preface
=======

We are pleased to present the industry’s first open-source book on the world’s most popular open-source network security engine, Suricata. The idea for this book emerged after it became obvious to us that many security practitioners using Suricata either struggle to effectively use the most powerful capabilities of the tool or simply don’t realize they exist. 

Each year, we speak at many industry conferences and train hundreds of users in workshops on behalf of the Open Information Security Foundation (OISF). In our engagements with the audience at these events, we have noticed that users share the common perception that Suricata is a classic signature-based intrusion detection system (IDS), albeit a powerful and high-performance one. Most fail to realize that the Suricata engine can also simultaneously produce protocol transaction logs and flow records that are correlated with the IDS alerts. These can be incredibly powerful for security analysts during an incident investigation or a threat hunt. And they can be even more powerful for the development of anomaly detection using Suricata.

So we decided to write a simple book to introduce the most powerful features and concepts developed in Suricata over its 12-year history. 

As you may be aware, there is a dedicated team of Suricata developers continuously working to improve Suricata and releasing new capabilities regularly. So, we decided to take a more open-source software development approach to the content and release cadence of the book in order to keep it relevant and up-to-date. 

The book is structured as a loose collection of chapters, each focused on a single subject area, such as Suricata rule writing or TLS detection and threat hunting. All its content is developed and managed on a `GitHub repository <https://github.com/StamusNetworks/suricata-4-analysts>`_ and is open to all who wish to comment or contribute ideas. Readers who are looking for a simple text edition may access all content there. Of course, we also package the book in PDF and eReader format for those who prefer source ‘code’ of the book.

The open-source format makes it a living book that will grow and evolve over time with ongoing input from the authors as well as contributions and feedback from the Suricata community. 

We would like to thank everyone at Stamus Networks for their support during the making of this book. And this book would not have been possible without the help of the amazing team at OISF.

.. note::

   This book is not meant to act as a replacement for the Suricata manual, which is an excellent reference tool for those installing and deploying the platform. Instead, The Security Analyst’s Guide to Suriata was written for the SOC analysts and threat hunters who have been tasked with effectively defending their network using Suricata. We aim to provide vital information on entry points and in-depth coverage for the most important Suricata features.

We welcome your feedback. Enjoy.
