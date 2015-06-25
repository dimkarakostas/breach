BREACH
=====================

Tools to execute [BREACH](http://breachattack.com) attack.

* breach.py
 * MitM proxy that sniffs TLS Packets, defragments TLS records and dumps header and payload.
* parse.py
 * Parse the output of breach.py to execute hill climbing.
* hillclimbing.py
 * Create the parameters needed by the js that executed the requests.
* breach_mitmdump.py
 * Install [mitmdump](https://mitmproxy.org/index.html) and configure it to print request and response code in the same line (see mitmdump_files folder). Run the script to start mitmdump and parse the output, calculating middle length value for each type of request.
* index.html
 * Minimal HTML page that contains the evil js.
* evil.js
 * Javascript that parses parameters needed from a file created by hillclimbing.py (and is in the same directory as evil.js and index.html) and issues requests on the endpoint.
* jquery.js
 * The jQuery library needed for evil.js. You can use the online version from [here](http://code.jquery.com/jquery-2.1.4.min.js).