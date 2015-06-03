# README #

nMASE : A Search Engine for Network Trace

A Search Engine which records and analyzes network activity and provides the user with ranked results through a web interface.

*Describe detailed working of project*

*Describe features of project*

This search engine is divided in 3 modules -
* Packet capture module (packetlogger.c) : Captures packets through PF_RING API and generates packet capture file, flow records and bitmap indices.

* Metadata extractor (metadata_extractor.py) : Reads the packet capture file and flow record file of a given time slot. Generates the JSON files for metadata.

* IR and Query processing module (Django project) : Accepts the query from user, performs query processing, retrieves the relevant results from JSON files and bitmap search and displays them in ranked format.


Dependencies:
-

Installation and running instructions:
-

Description of files and folders:

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
