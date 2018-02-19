# DNS Proxy

DNS proxy listens for incoming DNS requests (A,NS,MX,TXT,SRV..) on the local
interface (UDP only) and resolves correct addresses by using an external PHP
script, using standard HTTP(S) requests.

If you can't access VPN or tunnels  to resolve names externally (TOR users),
DNSProxy is a simple and efficient solution.

All you need to start resolving anonymous DNS is a PHP server hosting the
*ns.php* resolver script. This software is completeley  TOR-friendly, it 
requires minimal resources.

## Headline: why DNSP ?
This is a new idea in terms of transport of DNS outside of it's original scope.
This proxy project might well evolve in direction of having an IP protocol number 
assignement, or something like that.

## Building

Building is easy on Mac and Ubuntu, CentOS, Fedora... Probably UNIX and Windows.
Based on curl libs, pthread, TLS and other standard libraries

For debian/ubuntu users:  
`apt-get install libcurl4-openssl-dev`

Once done installing pre-requisites, compile with:
`make`
or
`gcc dnsp.c -W -lcurl -g -lpthread -DTLS -rdynamic -lrt -o dnsp`

## Installing

# STEP 0
Deploy the **ns.php** on a webserver, possibly not your local machine.
If you ignore how-to carry on such a task, or you do not have access to such a 
webserver, just use my webservice, as per following examples.

# STEP 1
Setup a caching proxy, on the local machine or on a remote host, and feed the 
parameters of your HTTP caching/proxy server to the *dnsp* program (see host and
port parameters, -H and -r).

# STEP 2
Compile the *dnsp* binary by running provided build commands (make, for example)

## Testing

To test if DNS proxy is working correctly, first run the program as following, by
filling in Your favorite TOR proxy address:

```bash
dnsp -l 127.0.0.1 -w 443 -s https://www.fantuz.net/ns.php
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
 few milliseconds, after the first recursive resolution...

## Usage scenario, examples

```bash
 # You can use a caching HTTP proxy
dnsp -p 53 -l 127.0.0.1 -h 127.0.0.1 -r 8118 -w 80 -s https://www.fantuz.net/ns.php

 # You want just to surf anonymously, using the HTTP/DNS service without HTTP caching proxy
dnsp -p 53 -l 127.0.0.1 -s https://www.fantuz.net/ns.php

 # HTTP vs HTTPS modes
dnsp -p 53 -l 127.0.0.1 -w 80 -s http://www.fantuz.net/ns.php
dnsp -p 53 -l 127.0.0.1 -w 443 -s https://www.fantuz.net/ns.php
```

In this example, DNS proxy listens on local UDP port 53 and sends the 
request to the PHP script hosted at the example address, eventually through
proxy (i.e. TOR, squid, charles).

You can rely on your favourite HTTP/HTTPS proxy server, should you need response caching.
Any polipo, squid, nginx, Varnish, charles, SOCKS, TOR, will work properly with DNSP.

You can also run DNSP through HTTP(S) without proxy, directly attaching the DNSP server to
the remote resolver webservice.

**IMPORTANT:** Please, don't use the script hosted on my server as demonstration.
It might be subjected to umpredicted change, offlining, defacing....
Instead - host yourself as many *ns.php* scripts as you can, or send it on a friend's server!
The more DNSP resolvers, the less DNS queries will be traceable (TOR leaking problem).

```bash
 dnsp 1.5
 usage: dnsp -l [local_host] -p [local_port] -h [proxy_host] -r [proxy_port] -w [lookup_port] -s [lookup_script] -

 OPTIONS:
      -l		 Local server address
      -p		 Local server port	(optional, defaults to 53)
      -H		 Cache proxy address	(strongly suggested)
      -r		 Cache proxy port	(strongly suggested)
      -u		 Cache proxy username	(optional)
      -k		 Cache proxy password	(optional)
      -s		 Lookup script URL
      -w		 Lookup port		(optional, defaults to 80/443 for HTTP/HTTPS)
      -t		 Stack size in format	0x1000000 (MB)
      -v		 Enable DEBUG
      -S		 Enable HTTPS

 Example HTTP+proxy   :  dnsp -p 53 -l 127.0.0.1 -r 8118 -H 127.0.0.1 -w 80 -s http://www.fantuz.net/ns.php
 Example HTTPS direct :  dnsp -p 53 -l 127.0.0.1 -w 443 -s https://www.fantuz.net/ns.php

```
## Changelog:

Version 1.5 - February 2018:
* fixed README and easen installation/testing procedure
* soon to get on DNSSEC
* deleted some files
* added Arduino double ethernet shield script
* will soon add the arduino-ethernet library with the added select() function
* added the GO version made by chinese people, inspired at my DNSP software
* other thought pending

Version 1.01 - March 2017:
* going back to either threads or vfork...
* want to implement DNSSEC somehow
* did improve code readability
* done more crashtest, memleak, timing tests
* it really works with millions query !
* published and improved a Varnish configuration as well

Version 1.01 - April 2015:
* HTTPS resolver support (even more privacy)
* Multithreading listener/responder
* Better nginx/polipo setup
* Stack size option
* Will add TCP listener/responder soon
* Some issue to set the proper ETag on polipo

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
