# DNS Proxy

DNS proxy listens for incoming DNS requests (A,NS,MX,TXT,SRV..) on the local
interface (UDP only) and resolves using an external PHP script, through 
simple HTTP requests.

If you can't use tunnels to resolve names externally (i.e. TOR users),
DNS proxy is a simple and efficient solution.

To work, it needs to know a PHP-enabled external server, completeley 
TOR-friendly.

## Building

For debian/ubuntu users:  

`apt-get install libcurl4-openssl-dev`

then

`gcc dnsp.c -lcurl -g -lpthread -DTLS -o dnsp`

## Usage 

```bash
dnsp -p 53 -l 127.0.0.1 -h 127.0.0.1 -r 8118 -w 80 -s https://www.fantuz.net/nslookup.php
```
In this example, DNS proxy listens on local UDP port 53 and sends the HTTPed
requests to PHP external script through the 10.0.0.2:8080 proxyi (TORed ?).

**IMPORTANT:** Please, don't use the script hosted on my server as demonstration.
It might be subjected to umpredicted change, offlining, deface.
Instead - host yourself the nslookup.php script, and spread it on a friend's server!
The more we are, the less DNS becomes a 'trackable' TOR leak.

```bash
 dnsp 1.01
 usage: dnsp -l [local_host] -h [proxy_host] -r [proxy_port] -w [webport] \
	-s [lookup_script] -t [stack_size]

 OPTIONS:
      -l		 Local server host
      -p		 Local server port
      -h		 Remote proxy host
      -r		 Remote proxy port
      -u		 Proxy username (optional)
      -k		 Proxy password (optional)
      -s		 Lookup script URL
      -w		 Webserver port (optional, default 80)
      -t		 Stack size in format 0x1000000 (MB)
      -v		 Enable DEBUG logging

 Example: dnsp -p 53 -l 127.0.0.1 -h 127.0.0.1 -r 8118 -w 80 \
	-s https://www.fantuz.net/nslookup.php

```
## Testing

To test if DNS proxy is working correctly, first run the program as following, by
filling in Your favorite TOR proxy address:

```bash
dnsp -l 127.0.0.1 -h 127.0.0.1 -r 8118 -w 443 -s http://www.fantuz.net/nslookup.php
```

then, try to resolve an hostname using the **dig** command:

```bash
dig www.google.com @127.0.0.1
```

The result must be something like this:

```
; <<>> DiG 9.8.1-P1 <<>> www.google.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29155
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.google.com. 		IN	A

;; ANSWER SECTION:
www.google.com.		3600	IN	A	173.194.64.106

;; Query time: 325 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Fri May 17 11:52:08 2013
;; MSG SIZE  rcvd: 48
```

When You properly implement cache on the webserver, answers will come back in
 few milliseconds, after the firs recursive resolution.

## Changelog:
Version 1.01 - April 2015:
* HTTPS resolver support (even more privacy)
* Multithreaded (while forked)
* Better nginx/polipo setup
* Stack size option
* Will add TCP listener/responder soon

Version 0.99 - July 2014:
* Add HTTP port selection
* Add NS, MX, AAAA, PTR, CNAME and other resolving capabilities.
* Code cleanup and performance review.
* Implementation with nginx and memcache and load testing 

Version 0.5 - May 17 2013:
* Add proxy authentication support
* port option is now optional (default is 53)
* Fixed compilation error
* Minor bug fixes

Version 0.4 - November 16 2009:
* Now using libCurl for http requests
* Implemented concurrent DNS server
* Bug fixes
* Code clean

Version 0.1 - April 09 2009:
* Initial release
