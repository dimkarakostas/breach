Use the following script for network debugging purposes.

* breach_mitmdump.py
 * Install [mitmdump](https://mitmproxy.org/index.html) and configure it to print request and response code in the same line (see below). Run the script to start mitmdump and parse the output, calculating middle length value for each type of request.

Replace the relative files that mitmproxy uses with these.

Debian path: /usr/local/lib/python2.7/dist-packages/

* libmproxy
 * dump.py : Print output in one line.
 * utils.py : Print length in byte format.
 * encoding.py : Disable automatic unzip of html page (mitmproxy view mode only).
* netlib
 * http.py : Create chunked (gziped plaintext) file and add chunk markers in breach.log in order to find TLS record and TCP packet correspondence.
* ~/.mitmproxy
 * common.conf : Add default proxy address and port.
