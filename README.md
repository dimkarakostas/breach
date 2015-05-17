BREACH
=====================

Tools to execute [BREACH](http://breachattack.com) attack.

* breach.py
 * MitM proxy that sniffs TLS Packets, defragments TLS records and dumps header and payload.
* parse.py
 * Parse the output of breach.py to execute hill climbing.
* index.html
 * Javascript code to implement multiple requests on endpoint, bypassing Huffman encoding.
* breach_mitmdump.py
 * Install [mitmdump](https://mitmproxy.org/index.html) and configure it to print request and response code in the same line (see mitmdump_files folder). Run the script to start mitmdump and parse the output, calculating middle length value for each type of request.