# DNS Proxy

DNS proxy listens for incoming DNS requests (A,NS,MX,TXT,SRV..) on the local
interface (UDP only) and resolves correct addresses by using an external PHP
script, using standard HTTP(S) requests.

If you can't access VPN or tunnels  to resolve names externally (TOR users),
DNSProxy is a simple and efficient solution.

All you need to start resolving anonymous DNS is a PHP server hosting the
*nslookup.php* resolver script. This software is completeley  TOR-friendly, it 
requires minimal resources.

## Disclaimer
IF ANONIMITY IS A CONCERN, make sure to host NS.PHP on a good trustable server !
To be clear, the ns.php script DOES do DNS request, which relies on mechanisms
of resolving DNS that are normally controlled by the hosting provider (and
hence, supposedly optimised for best speed and caching), mechanisms that are
outside the scope of DNSP as a software. That said, you MUST use an external
server that you trust and you can deploy on. As suggested, having the 
ns.php script running locally makes no sense and WILL make ALL of your DNS
queries leaking. Useful for testing purposes only !!
IF ANONIMITY IS A CONCERN, make sure to host NSLOOKUP.PHP on a good trustable server !

## Headline: why DNSP ?
This is a new idea in terms of transport of DNS outside of it's original scope.
This proxy project might well evolve in direction of having an IP protocol number 
assignement, or something like that.

## Architecture
```
               +------------------------+
   +---------  |DNSP listens on original|<------------+
   |           | socket used by HTTP(S) |             |
   |           +----------------------+               | reply is sent on HTTP(S)
   |                    ^                             | back to DNSP which then
   |                    | if valid answer  in         | forges a proper UDP/DNS response
   |                    | local HTTP caches,          | as per RFC1035 & following.
   |                    | do not exit localhost       |
   v                    |                             :
 +----------+   +--------+-------+           /-------------------\
 |client/OS | --+   DNSProxy     +---------->|                   |
 |  issues  |   +----------------+           | HTTP(S) webserver |
 | DNS qry  |   | can modify TTL |           |  (nslookup.php)   |
 |(syscall) |   | blacklist,cache|           | does the real job |
 +---+------+   +----------------+           \-------------------/
     :                                  	  ^
     |  qry goes to DNSP daemon on 127.0.0.1:53   |
     +--------------------------------------------+
	and is being transported on HTTP, with
           no use of DNS or UDP whatsoever 
```

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

### STEP 0, having access to the HTTP(S) nameserver webservice
Deploy the **ns.php** on a webserver, possibly not your local machine.
If you ignore how-to carry on such a task, or you do not have access to such a 
webserver, just use my webservice, as per following examples.

### STEP 1, having access to an HTTP(S) proxy, optional but suggested
Setup a caching proxy, on the local machine or on a remote host, and feed the 
parameters of your HTTP caching/proxy server to the *dnsp* program (see host and
port parameters, -H and -r).

### STEP 2, simple compilation of DNSP binary prior to running
Compile the *dnsp* binary by running provided build commands (make, for example)

## Caching answers in the network

When You properly implement cache on the webserver, answers will come back in
few milliseconds, after the first recursive resolution...

Tested on CloudFlare, Google Cloud Platform, Docker, etc

## Usage examples

```bash
 # You can use a caching HTTP proxy
dnsp -p 53 -l 127.0.0.1 -h 127.0.0.1 -r 8118 -w 80 -s https://www.fantuz.net/nslookup.php

 # You want just to surf anonymously, using the HTTP/DNS service without HTTP caching proxy
dnsp -p 53 -l 127.0.0.1 -s https://www.fantuz.net/ns.php

 # HTTP vs HTTPS modes
dnsp -p 53 -l 127.0.0.1 -w 80 -s http://www.fantuz.net/nslookup.php
dnsp -p 53 -l 127.0.0.1 -w 443 -s https://www.fantuz.net/nslookup.php
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
Instead - host yourself as many *nslookup.php* scripts as you can, or send it on a friend's server!
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

 Example HTTP+proxy   :  dnsp -p 53 -l 127.0.0.1 -r 8118 -H 127.0.0.1 -w 80 -s http://www.fantuz.net/nslookup.php
 Example HTTPS direct :  dnsp -p 53 -l 127.0.0.1 -w 443 -s https://www.fantuz.net/nslookup.php

```
## Changelog:

Version 1.5 - February 2018:
* fixed README and easen installation/testing procedure
* soon to get on DNSSEC
* deleted some files
* added Arduino double ethernet shield script
* will soon add the arduino-ethernet library with the added select() function
* added the GO version made by chinese people, inspired at my DNSP software
* having few issues caching on ClouFlare-alike caches (304 not showing anymore ? want more of them).
* everything works as usual: caching is lazy, CURL follows redirects (301, I want less of them)
* other thought and implementations pending

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

## Testing

To test if DNS proxy is working correctly, first run the program as following, by
filling in Your favorite TOR proxy address:

```bash
dnsp -l 127.0.0.1 -w 443 -s https://www.fantuz.net/nslookup.php
```
or
```
dnsp -l 127.0.0.1 -w 443 -s https://php-dns.appspot.com/helloworld.php
```

then, try to resolve an hostname using the **dig** command against your localhost DNSP:

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

If the test query works, you can safely replace "nameserver" entries on /etc/resolv.conf
to start pointing ALL DNS TRAFFIC TO DNSP, leveregin DOH (DNS-over-HTTP).

To test if nslookup.php is correctly deployed (eventually on your protected server), replace values accordingly to 
your configuration, here's mine:
```
# curl -s -H "Host: www.fantuz.net" -H "Remote Address:104.27.133.199:80" -H "User-Agent:Mozilla/5.0 \
(Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 \
Safari/537.36" 'http://www.fantuz.net/nslookup.php?host=fantuz.net&type=NS' | xxd
# curl -s -H "Host: php-dns.appspot.com" -H "User-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36" \
'http://php-dns.appspot.com/helloworld.php?host=fantuz.net&type=NS' | xxd
```

Values should end with bits 0d0a:
```
00000000: 7364 6e73 332e 7668 6f73 7469 6e67 2d69  sdns3.vhosting-i
00000010: 742e 636f 6d0d 0a                        t.com..
```

## References:

* https://www.reddit.com/user/fantamix/comments/7yotib/dnsp_a_dns_proxy_to_avoid_dns_leakage/
* https://www.reddit.com/r/hacking/comments/7zjbv2/why_to_use_a_dns_proxy_why_shall_it_be/
* https://tools.ietf.org/html/draft-ietf-dnsop-dns-wireformat-http-01
* https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-03

## License
MIT license, all rights free.

