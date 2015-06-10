# README #

nMASE : A Search Engine for Network Trace
-

A Search Engine which records and analyzes network activity and provides the user with ranked results through a web interface.

nMASE is a network monitoring tool created for network administrators. It provides an intuitive search engine interface for administrators to search recorded network activity and get the relevant information quickly.

Protocols currently supported -

Data link layer 	: Ethernet

Network layer		: IPv4

Transport layer		: TCP, UDP

Application layer	: HTTP, DNS, FTP, SMTP

This search engine is divided in 3 modules -
* Packet capture module (packetlogger.c) : Captures packets through PF_RING API and generates packet capture file, flow records and bitmap indices.

* Metadata extractor (metadata_extractor.py) : Reads the packet capture file and flow record file of a given time slot. Generates the JSON files for metadata.

* IR and Query processing module (Django project) : Accepts the query from user, performs query processing, retrieves the relevant results from JSON files and bitmap search and displays them in ranked format.

Detailed working:
-

When the packet capture module is started, it creates a directory in CWD with current day as its name. (e.g. if date is 31/12/2014, directory "31" will be created) Inside this directory, another directory with current hour as name is created. (e.g. if time is 2:34pm, directory "14" will be created) For each time slot of 1 hour, a new directory is created. (e.g. if this module is run from 2:34pm to 4:34pm, the directories 14, 15, 16 will be created inside outer day directory. Hence, a day directory can have at most 24 subdirectories. (each belonging to one-hour time slot in that day) If any directory already exists, its contents will be overwritten. nMASE can store network activity of past 30-31 days, after which, the old data will be overwritten (Since days will be repeated in the next month, again starting from 1, 2, 3, ... 30/31).

Each hour directory contains the captured and processed data during that one-hour time slots. This directory contains following files -
- Packet capture file (packetcap.capture) : Incoming packets are simply appended to this file in the order of their arrival. In addition, Our additional custom header is prefixed to all packets. One of the fields in our custom header is offset link of the next packet in the same network flow. These offset links are used to chain the packets belonging to same flow. Thus, if offset of first packet from a flow is obtained, the rest packets in the flow can be easily fetched by following this chain. The offset of first packet is stored in the next file.

TODO: Explain the need

- Flow record file (flow_rec) : This file contains flow records of network flows established during the corresponding time slot. Each record has following fields - Source IP, Source port, Destination IP, Destination port, Offset of first packet. This file can give a quick summary of all the flows encountered. A flow record is appended to this file whenever we encounter the first packet of a new flow. Each flow has a unique ID.

- Compressed bitmap indexes (*.bitmap) : Flow record file can tend to get very large and hence linear searching on it would take considerable time. Bitmap indexes are search indexes created to enable searching on IP addresses, port numbers and transport layer protocol. There are different bitmap indexes created for source IP, destination IP, source port, destination port and transport protocol. Since bitmaps tend to get very large, they are compressed using WAH (Word Aligned Hybrid) Scheme.
These bitmaps are created and kept in main memory until the time slot is finished, after which, they are written to the files inside their hour directory.

TODO: Explain the structure of bitmaps. 

As the clock strikes an hour, all the bitmaps are written to the file, the essential data structures used for packet chaining are freed, a new directory for the next hour is created and all the incoming packets after that moment are written in the new slot directory. Same procedure is followed. Now the second module can begin processing of the previous slot directory since no more stuff will be written into that. 

Second module (metadata extractor) performs two important functions -

1. Determining application layer protocol of flows
2. Extracting metadata and storing in JSON files

For determining application layer data, we use feature based protocol determination. We do not rely on port numbers alone because they are prone to errors due to tunneling. For each flow, the features of first 10 packets are observed. Probabilities are assigned to the 4 application layer protocols based on the occurence of their features in these packets. If probability of a protocol crosses a certain threshold value, that flow is labelled with the matching protocol. 

TODO: Explain the different factors used in the process and their corresponding weightages.

After the application layer protocol is known, we move to the protocol-specific metadata extraction using deep packet inspection. Only the important and useful information is extracted from application layer headers/data and is stored in JSON files with key being the unique ID of each flow. Also, a score is assigned to each flow based different factors of interestingness to the administrator.
This module performs another important function of attack pattern matching. Currently only HTTP attack pattern matching is supported. The file "attack.txt" in root directory stores the patterns in "<attack_name>:<pattern>" format. The program reads this file and tries to match the patterns with HTTP headers it encounters. If a match is found, the score of that flow is increased and entry is made in JSON structure of that flow. 

After the execution of this module, two JSON files are obtained - metadata.json and aggr.json in the same hour slot which the module was run on. The metadata.json file contains all the extracted important information/metadata in verbose format. The aggr.json file is just an abstracted or shorter version of metadata.json which is useful for faster searching. 

TODO: Explain the structure of JSON files

TODO: Explain the scoring factors

Third module (Information Retrieval and Query processing) is developed in django framework and present inside the folder of same name. First the django server needs to be started. The homepage can be accesed by typing http://127.0.0.1:8000/nmase/
The user can enter the query in corresponding box and select the time slot on which she wants to search. The query is then processed on django backend. Keyword based technique is used for query processing. Basically, when the query is received, different keywords are identified from it, i.e. IP address, port numbers, protocol name, URL, file name etc. Source and Destination IP addresses are distinguished based on the occurence of keywords such as "to", "from", "towards" etc. A table is then built from the identified keywords and their values. This table can be thought of as intermediate form of query. 

This intermediate form is then passed to the core search function. (present in searchfunctionnew.py) This search function performs following tasks -

* Identifying different keywords from the query
* Separating IP addresses and port numbers present in query into source and destination
* Invoking the bitmap search executable (./bitmap_search_comp_new) as many times as required depending upon the number of IP address and port numbers present in the query. This executable accepts the IP addresses, port numbers and slot path in which to search for. It then searches on the compressed bitmaps present in that slot and returns the matching flow IDs to the caller search function. 
* Reading aggr.json and searching for application layer keywords from query. Extracting the information of flows if they are matching.
* Reading metadata.json to fetch additional information for only the matching flows. Each search result will have this additional information with it.  
* Calculating dymanic scoring factors which affect the ranking. Computing the final score of all matching flows. Each search result belongs to one matching flow.
* Creating the dataset for graphs which will be shown with search results
* Sorting the search results (flows) in decreasing order of their score and returning the search results, metadata information and datasets for graphs
* Rendering the search page, along with search results, graphs and showing it to the user.

The web interface for this module is developed in HTML, CSS, Javascript, jQuery. The main search page has a query text box, along with a widget to select a time slot. When the user clicks search, a list of relevant search results is returned to them. User can hover over a search result to see the additional information/metadata about that flow in the right side pane. Presence of any HTTP attack is highlighted here. Clicking on a search result will take user to another page where they can see raw packet information of all the packets in corresponding flow. Clicking on 'graphs' tab will show statistical information about the search results currently returned, like the protocol distribution, source IP distribution and destination IP distribution. If any IP address is present in the query, the system will also try to determine if that IP address is up right now, by performing an AJAX call in the background. Its result is shown on the top of search results page. The user can log in to see their most recent and most frequent queries in the right side news feed.

One important functionality provided by nMASE is facility to import PCAP files. The user can upload their own PCAP files through the link provided on homepage. Once the PCAP file is uploaded, nMASE will automatically run the first and second module on the packets fetched from this PCAP. This will generate all the flow records, bitmaps indexes and JSON files like a conventional run. The user can then search through the contents of this PCAP file, just the way they are able to do this with regular network packet captures. 

**Overview of nMASE Architecture**
![Alt text](/architecture-final.png?raw=true "Architecture")

Features of nMASE:
-
* On the fly packet capture
* Deep packet inspection
* Ability to import PCAP files
* Faster search with indexes and special, lightweight file formats
* Ranking of packet flows based on various factors
* Support for natural language queries
* Customized experience for users based on authentication
* Efficient use of RAM
* Web interface, accessible from anywhere in network

Dependencies:
-
* PF_RING kernel module installed
* Python 3.4
* Django framework 1.7

Installation and running instructions:
-

Description of files and folders:
-

/django - Project folder of third module, Query processing, IR and web interface part.

/doc - documentation of the code and other important statistics, performance measurements etc.

/include - all the header files and library functions

/utilities - misc programs not directly part of the project, but created to quickly check and verify the output of other programs.

packetlogger.c - First module. Captures packets, logs them, creates flow records and bitmap indices.

importlogger.c - Variation of first module. Reads packets from PCAP file instead of NIC.

bitmap_search_comp_new.c - search through generated WAH encoded bitmaps.

attack.txt - Stores attack patterns of HTTP attacks to be detected. Structure of each line is "<attack_name>:<attack_pattern>" (without quotes).

compile - shell script to compile all necessary C files.

errors - Log file which stores information about detected attacks.

metadata_extractor.py - Second module. Analyzes and processes packet information generated from first module. Extracts important information (metadata) and stores in JSON files in the same slot directory.

startserver - shell script to start the django server

### What is this repository for? ###

* Quick summary
* Version
* [Learn Markdown](https://bitbucket.org/tutorials/markdowndemo)
