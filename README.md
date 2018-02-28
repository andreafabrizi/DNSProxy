# DNS Proxy

DNS proxy listens for incoming DNS requests (A,NS,MX,TXT,SRV..) on the local
interface (UDP only) and resolves such queries by using an external PHP
script, using standard HTTP(S) requests. It will then recreate the well-formed
UDP packet on 127.0.0.1 and send it back to the client.

If you can't access "secured" VPN or tunnels  to resolve names externally (i.e.
TOR users), DNSProxy is a rapid and efficient solution for you.

In order to resolving "anonymous DNS", all you need is a PHP-server hosting the
*nslookup.php* resolver script. This software is completeley  TOR-friendly,
requires minimal resources.

## Headline: why DNSP ?
This is a new idea in terms of transport of DNS outside of it's original scope.
This proxy project might well evolve in direction of having an IP protocol number 
assignement, or something like that.
DNS-over-HTTP is currently being evaluated by IETF as workgroup/proposal.

## Disclaimer
WHEN FULL-ANONIMITY IS A CONCERN, make sure to host *nslookup.php* on a trustable server !

To be clear, the PHP script DOES DO the underlying (infamously leaking) "system call", the
"classic DNS request". Such system call relies on different mechanisms to resolve DNS, and in
case of hosting providers, such mechanism are managed by the hosting provider.
Hence, supposedly optimised for best speed and caching. Such system calls are therefore outside
the control of DNSP as a software: all DNSP does is tunneling **and** avoids leakage of UDP qry.

That said, you MUST use an external server that you trust and you can deploy on !
And do not forget to check that 127.0.0.1 becomes your unique system-wide resolver.

Beware, having the PHP script running on the same local machine (not using a remote webservice)
makes no sense and WILL make ALL of your DNS queries leaking. Useful for TESTING purposes only !!

## Architecture
```
              +--------------------------+
   +----------| DNSP listens on original |<----------+
   |          | socket used by HTTP(S)   |            |
   |          +--------------------------+            | reply is sent on HTTP(S)
   |                     ^                            | back to DNSP (CURL) which
   |                     | if valid answer found      | creates a proper UDP/DNS
   |                     |  in local HTTP cache,      |  response, in accordance
   |                     | faster, same security      |   with RFC1035 et al.
   v                     |                            :
 +----------+   +--------+--------+           /-------------------\
 |client/OS | --+    DNSProxy     +---------->| webservice HTTPS  |
 |  issues  |   +-----------------+           |                   |
 | DNS qry  |   | can modify TTL  |           |   nslookup.php    |
 |(syscall) |   | blacklist,cache |           | does the real job |
 +---+------+   +-----------------+           \-------------------/
     :                                  	        ^
     |  UDP query goes to DNSP daemon on 127.0.0.1:53   |
     +--------------------------------------------------+
	and is being transported on HTTP, with
           no use of DNS or UDP whatsoever 
```

## Building

Building is easy on Linux, Mac... On UNIX and Windows might be, didn't test much.
Based on CURL C library, pthread, SSL/TLS and other standards.

For debian/ubuntu users:  
`apt-get install libcurl4-openssl-dev`

Once done installing pre-requisites, compile with:
`make all`
or manually
`gcc dnsp.c -W -lcurl -g -lpthread -DTLS -rdynamic -lrt -w -o dnsp`

## Installing

#### STEP 0, having access to the HTTP(S) nameserver webservice
Deploy **nslookup.php** on a webserver, possibly not your local machine (see DISCLAIMER).
If you ignore how-to carry on such a task, or you do not have access to such a 
webserver, just use my webservice, as per following examples.

#### STEP 1, having access to an HTTP(S) proxy, optional but suggested
Setup a caching proxy, on the local machine or on a remote host, and feed the 
parameters of your HTTP caching/proxy server to the *dnsp* program (see host and
port parameters, -H and -r).

#### STEP 2, simple compilation of DNSP binary prior to running
Compile the *dnsp* binary by running provided build commands (make, for example)

## Caching answers in the network

DNS cache is populated with standard HTTP answers provided by the remote webservice 
(which in turn uses PHP headers in nslookup.php to influence such caching accordingly).
A local caching-only proxy (on any LAN address for example) will help caching 
HTTP 304 "Not Modified" answers. DNS answers will come back in matter of milliseconds,
after the first recursive resolution done eventually on the remote webservice...

Tested on CloudFlare, Google Cloud Platform, Docker, NGINX, Apache, etc

## Usage examples


 # You want just to surf anonymously, using the HTTPS/DNS service without HTTP caching proxy
 # but still want DNS traffic to be to be encrypted (simplest mode):
```bash
dnsp -p 53 -s https://www.fantuz.net/nslookup.php
```
# If you can leverage the use of local HTTP caching proxy running on non-default port (!=1080):
```bash
dnsp -p 53 -l 127.0.0.1 -h 127.0.0.1 -r 8118 -s https://www.fantuz.net/nslookup.php
```
 # HTTP vs HTTPS modes
```bash
dnsp -s http://www.fantuz.net/nslookup.php
dnsp -s https://www.fantuz.net/nslookup.php
```

In this example, DNS proxy listens on local UDP port 53, and reuests the PHP script, eventually through
additional proxy (i.e. TOR, enterprise-proxy, locked-down country, etc).

Should you be willing to perform "response caching" (and sharing), you can rely on your favourite
HTTP/HTTPS proxy server, as any of polipo, squid, nginx, Varnish, charles, SOCKS, TOR, will work 
properly with DNSP.

You can also run DNSP through HTTP(S) without any caching or extra proxy, directly attaching the DNSP server to
the remote resolver webservice (the nslookup.php can be hosted anywhere, i.e. on Google Cloud Platform).

**IMPORTANT:** Please, don't use the script hosted on my server(s) as they serve as demo-only.
They might be subject to unpredicted change, offlining, defacing.... Trust your own servers, and 
host yourself as many *nslookup.php* scripts as you can, or send it on a friend's server!

The more DNSP resolvers around the world, the less DNS queries will be traceable (TOR leaking problem).

```bash

 dnsp 1.5, copyright @ 2018 Massimiliano Fantuzzi, HB3YOE, MIT License

 usage: dnsp [-l [local_host]] [-p [local_port:53,5353,..]] [-H [proxy_host]] [-r [proxy_port:8118,8888,3128,9500..]] 
		 [-w [lookup_port:80,443,..]] [-s [lookup_script]]

 OPTIONS:
      -l		 Local server address	(optional)
      -p		 Local server port	(optional, defaults to 53)
      -H		 Cache proxy address	(strongly suggested)
      -r		 Cache proxy port	(strongly suggested)
      -u		 Cache proxy username	(optional)
      -k		 Cache proxy password	(optional)
      -s		 Lookup script URL	(mandatory option)
      -w		 Lookup port		(obsolete, defaults to 80/443 for HTTP/HTTPS)
      -t		 Stack size in format	0x1000000 (MB)

 TESTING/DEV OPTIONS:
      -v		 Enable DEBUG
      -C		 Enable CURL VERBOSE, useful to spot cache issues or dig down into HSTS/HTTPS quirks
      -I		 Upgrade Insecure Requests, HSTS work in progress
      -R		 Enable CURL resolve mechanism, avoiding extra gethostbyname, work in progress

 Example DNS/HTTPS direct :  dnsp -s https://www.fantuz.net/nslookup.php
 Example DNS/HTTP w/cache :  dnsp -r 8118 -H 127.0.0.1 -s http://www.fantuz.net/nslookup.php
```
## Changelog:

#### TODO and WIP:
* get on DNSSEC
* get on DOH and H2 in simple way (CURL)
* soon to add the arduino-ethernet library with the new select() function (sorry for delay, was easy)

#### Version 1.6 - March 2018:
* sneak peak: REDIS ready _via https://github.com/redis/hiredis_
* 
* more community = more test

#### Version 1.5 - February 2018:
* added IETF references and talk about DOH (wich does HTTP2, so single connection multiple streams)
* added Arduino double ethernet shield script
* fixed NS/CNAME answers (C) and resolver script (PHP)
* added the GO version made by chinese people, inspired at my DNSP software
* MIT License in accordance to transfer of rights operated via mail by Andrea
* everything works as usual: caching is lazy, CURL follows redirects (301, I want less of them)
* other thought and implementations pending
* fixed README and easen installation/testing procedure
* deleted some junk files, renamed dirs for clarity
* multiversion PHP 5/7, depending on hosting provider (due to slightly different implementation of print(), some headers, random css, substantial differences between h1/h2, etc).

#### Version 1.01 - March 2017:
* going back to either threads or vfork...
* want to implement DNSSEC somehow
* having few issues caching on ClouFlare-alike caches (304 not showing anymore ? want more of them).
* done more crashtest, memleak, timing tests
* it really works with millions query !
* published and improved a Varnish configuration as well

#### Version 1.01 - April 2015:
* HTTPS resolver support (even more privacy)
* Multithreading listener/responder
* Better nginx/polipo setup
* Stack size option
* Will add TCP listener/responder soon
* Some issue to set the proper ETag on polipo

#### Version 0.99 - July 2014:
* Add HTTP port selection
* Add NS, MX, AAAA, PTR, CNAME and other resolving capabilities.
* Code cleanup and performance review.
* Implementation with nginx and memcache and load testing 

#### Version 0.5 - May 17 2013:
* Add proxy authentication support
* port option is now optional (default is 53)
* Fixed compilation error
* Minor bug fixes

#### Version 0.4 - November 16 2009:
* Now using libCurl for http requests
* Implemented concurrent DNS server
* Bug fixes
* Code clean

#### Version 0.1 - April 09 2009:
* Initial release

## Testing

To test if DNS proxy is working correctly, you can use tcpdump. Or simply run the program as follows,
maybe just change the webservice address:

```bash
dnsp -l 127.0.0.1 -s https://www.fantuz.net/nslookup.php
```
Open a new terminal and invoke **dig** to resolve a sample hostname against your brand-new 
localhost instance of DNSP:

```bash
dig www.google.com @127.0.0.1
```
The result must be something like this, no errors or warning shall be trown:

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

If the test query works, you can safely replace the "nameserver" entries on /etc/resolv.conf
and immediately point ALL DNS TRAFFIC towards DNSP, leveraging DOH (DNS-over-HTTP) capabilites.

To test whether nslookup.php is correctly deployed and resolving, you could use **bash** (curl).
Replace URL value in accordance with script location. Here are two that I use to check my deploys:
```
# curl -s -H "Host: www.fantuz.net" -H "Remote Address:104.27.133.199:80" -H "User-Agent:Mozilla/5.0 \
(Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 \
Safari/537.36" 'http://www.fantuz.net/nslookup.php?host=fantuz.net&type=NS' | xxd

# curl -s -H "Host: php-dns.appspot.com" -H "User-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36" \
'http://php-dns.appspot.com/helloworld.php?host=fantuz.net&type=NS' | xxd
```

Values should end with bits 0d0a. on any server (HEX is easy to read):
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
MIT license, all rights included.

