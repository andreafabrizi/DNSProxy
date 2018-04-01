# DNS Proxy over HTTP(S)

## Why DNSP ?
This is a new idea in terms of transport of DNS outside of it's original design.
DNS-over-HTTP is currently being evaluated by IETF as workgroup/proposal.
(c.f. https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-03)
An header schema for HTTP/2 client has been outlined, WIP implementation.

There is no roadmap on my side, just the burning desire to see DoH being 
implemented and deployed. 

## How does it work ?
DNS proxy listens for incoming DNS requests (A,NS,MX,TXT,SRV..) on any
local interface chosen, on both UDP and TCP. It listens with threads, then 
when a query comes in, it parses and start resolving such queries, by using 
an external PHP script and standardised HTTP requests/headers (D-o-H compatible).

DNSP will take care to recreate a well-formed UDP/TCP packet in reply to client.

The core PHP-script can be hosted anywhere, i.e. on Google Cloud Platform.

Should you be willing to perform "response caching and sharing" you can rely 
on your favourite HTTP/HTTPS proxy server, as any of polipo, squid, nginx, 
Varnish, charles, SOCKS, TOR, *any HTTP proxy* will work properly with DNSP.

DNSP can be configured to cross through (and receiving Via) additional HTTP 
proxy (i.e. TOR, enterprise-proxy, locked-down countries).

Most of users will run DNSP directly through HTTPS w/out caching & extra proxy.
The DNSP server will just talk to remote resolver webservice, w/out any cache.

FYI, a cache is often availaible "in the network" when using HTTP, no real need
for an extra local cache (HTTP/2 and HTTPS make it difficult to cache locally).

If you can't access "secured" VPN tunnels to resolve names externally (i.e.
TOR users, Chinese walls), DNSProxy is a rapid and efficient solution for you.

As bonus, this software is TOR-friendly and requires minimal resources. Enjoy !

## Architecture
```
              +--------------------------+
   +----------| DNSP listens on original |<-----------+
   |          | socket used by HTTP(S)   |            |
   |          +--------------------------+            | reply is sent via HTTP(S)
   |                     ^                            |   back to DNSP/libCURL. 
   |                     |  if valid answer found     | then DNSP builds UDP/TCP
   |                     |   in local HTTP cache      |  response, in accordance
   |                     | the response is faster     |   with RFC1035 et al.
   |                     |  at the same security      |
   v                     |                            :
 +----------+   +--------+--------+           /-------------------\
 |client/OS | --+    DNSProxy     +---------->|  webservice HTTPS |
 |  issues  |   +-----------------+           |         -         |
 | DNS qry  |   | can modify TTL  |           | nslookup-doh.php  |
 |(syscall) |   | blacklist,cache |           | does the real job |
 +---+------+   +-----------------+           \-------------------/
   :                                  	                     ^
   | query goes to DNSP daemon on 127.0.0.1:53 (UDP or TCP)  |
   +---------------------------------------------------------+
 classic DNS except that messages are being transported over HTTP/2
      with no leackage of UDP whatsoever (see PRIVACY notes)
```

Features:
- being DNS-over-HTTP compliant, and even more (older standards supported).
- FOLLOWLOCATION, spawns threads to enable HTTP browser cache preemption for the benefit of the user experience.
- HTTP/2 ready. Talks HTTP/2 in different combination of ALPN, NPN, Update, SSL & co.
- HTTP/2 was set as the minimut base by DOH/IETF spec doc, so I wanted to conform (easy with libCURL or nghttp2).
- HTTP/2 PUSH being tested, for smoother and opportunistic DNS answers (remember, no ID field in doh!).
- ability to dump DNS response packet, then serve such content via local HTTP webserver
  (not in DNSP intents, but possible for the benefit and simplicity of DOH adoption !)
- ability to set specific headers according to cache requirements, i.e. translate DNS TTL validity to HTTP cache Validity :)

To recap, in order to start resolving "anonymous DNS" over HTTP, all you need is:
- a PHP-server hosting the *nslookup-doh.php* resolver script
- the C software, available in source or compiled (all libs linked within, Makefile does).

## Caching answers in the network

DNS cache is populated with standard HTTP answers provided by the remote webservice 
(which in turn uses PHP headers in nslookup.php to influence such caching accordingly).
A local caching-only proxy (on any LAN address for example) will help caching 
HTTP 304 "Not Modified" answers. DNS answers will come back in matter of milliseconds,
after the first recursive resolution done eventually on the remote webservice...

Tested on CloudFlare, Google Cloud Platform, Docker, NGINX, Apache, SQUID, polipo, memcache
REDIS... response times incredibly low, very scalable and smart solution, this DNSP !

## Examples provided for DNS and DNS-over-HTTP beginners:

#### You want just to surf anonymously using HTTPS/DNS service without HTTP caching proxy (simplest mode):
```bash
dnsp-h2 -s https://www.fantuz.net/nslookup-doh.php
```
#### Leverage the use of local HTTP caching proxy. Option "-H" to specify proxy's URI (URI!=URL)
```bash
dnsp -H http://192.168.3.93/ -r 8118 -s https://www.fantuz.net/nslookup-doh.php
dnsp -H http://aremoteproxyservice/ -r 3128 -s https://www.fantuz.net/nslookup-doh.php
```
#### HTTP mode w/out caching proxies and w/out HTTPS
```bash
dnsp -s http://www.fantuz.net/nslookup-doh.php

NB: Some parts of this "distributed cache" might be held on a CDN for a transient period.
An intermediate cache layer is often present nowadays, unless forbidden by headers or expiry.
Headers are your friends.

```

**IMPORTANT:** Please, don't use the script hosted on my server(s) as they serve as demo-only.
They might be subject to unpredicted change, offlining, defacing.... Trust your own servers, and 
host yourself as many *nslookup-doh.php* scripts as you can, or send it on a friend's server!

The more DNSP resolvers around the world, the less DNS queries will be traceable (TOR leaking problem).

```bash
 dnsp 2, copyright @ 2018 Massimiliano Fantuzzi, HB3YOE, MIT License

 usage: dnsp [-l [local_host]] [-p [local_port:53,5353,..]] [-H [proxy_host]] [-r [proxy_port:8118,8888,3128,9500..]] 
		 [-w [lookup_port:80,443,..]] [-s [lookup_script]]

 usage: dnsp-h2 [-l [local_host]] [-p [local_port:53,5353,..]] [-H [proxy_host]] [-r [proxy_port:8118,8888,3128,9500..]] 
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

 TESTING/DEV OPTIONS:
      -T		 Force TTL to be [int] (useful for autotest)
      -n		 Enable DNS DUMP
      -v		 Enable DEBUG
      -C		 Enable CURL VERBOSE, useful to spot cache issues or dig down into HSTS/HTTPS quirks
 WIP OPTIONS:
      -I		 Upgrade Insecure Requests, HSTS work in progress
      -R		 Enable CURL resolve mechanism, avoiding extra gethostbyname (DO NOT USE)
      -t		 Stack size in format	0x1000000 (MB)

 Example HTTPS direct :  dnsp-h2 -s https://www.fantuz.net/nslookup-doh.php
 Example HTTP direct  :  dnsp -s http://www.fantuz.net/nslookup.php
 Example HTTP w/cache :  dnsp -r 8118 -H http://myproxy.example.com/ -s http://www.fantuz.net/nslookup.php

```

## Building

Building is easy on Linux, Mac... UNIX and Windows as well.
Based on CURL C library, pthread, SSL/TLS and other strong standards.
A recent version of CURL is needed to leverage HTTP/2 capabilities.

`apt-get install libcurl4-openssl-dev curl libsslcommon2-dev \
libssl-dev ca-certs brotli gnutls-bin openssl libtlsh-dev`

Once done with installing such pre-requisites, compile with classic:
`make all` or simply `nake`

## Installing

#### STEP 1. Create access to an HTTP(S) nameserver webservice
Deploy **nslookup.php** on a webserver, possibly not your local machine (see DISCLAIMER).
If you ignore how-to carry on such deploy task or you do not have access to any of
such webservers, just use my own webservice, as suggested in usage examples.

#### STEP2 2, Have access to an HTTP(S) proxy, optional but preferable
Setup an HTTP caching proxy on the local machine or on a remote host. Feed host and
port of your proxy server to the *dnsp* program arguments.

#### STEP 3: compile DNSP binary
Compile the *dnsp* binary by running provided build commands (make, for example)

## Integration, easy with standards:

DNSP has been build keeping in mind _simplicity_ and _standardness_.
Most of us will know that -on a modern Linux box- an extra layer of caching DNS messages is
provided by nscd or dnsmasq services. Even in presence of such caches, UDP+TCP DNS traffic
accounts today for a sensible and quite constant bandwidth consumption.

DNSP is _not_ an alternative to such caching services. They can coexist if needed. In a way,
DNS can be integrated to work closely with **DNS services** in empowering a more distributed 
cache, or might be dropping the HTTP cache as a whole, in favour of clever methods of doing the
same operation: certify and distribute DNS by means of HTTP standardised methods.

Infact, in a scenario of CDN, anycasting and load balancing, the HTTP (insecure) cache is becoming
less and less effective, due to the added security layers and increasing speed between peers
(hence the lack of the need of an HTTP proxy). A thing I will soon look into is "UDP multiplexing", 
aka QUIC. I still believe UDP has more to show. I just play and have fun learning programming.

As the whole internet has been, a **standardised work in progress** since the past 30-40 years,
so DNSP is: an experimental software, a community tool.

DNSP presents itself as an alternative transport method of the same good old and fascinating DNS.
As I often stated, DNSP was conceived as a way to help overcoming censorship and trackability via DNS.
As you might question yourself, yes, any **DNS-over-HTTP** will leave a trace, just the
trace will be in a different place, not on the UDP level anyway.

I never meant to say that DNSP is faster or better than any other, is just pretty new on its own.
Is a big piece of curly/thready code that helps people _transporting_ and _sharing_ DNS.

## Changelog:

#### TODO:
* get on DNSSEC as extra
* adding NGHTTP2 along or in place of CURL. Would be a better/faster way to support H2 dialog
* implementing request/response headers PHP, according to new content type "application/dns"

#### WIP:
* use Warning headers to signal something

#### UNOFFICIAL DOH SERVER LIST
* 1.1.1.1
* 8.8.8.8
* 9.9.9.9

#### Version 2 - March 2018:
* DOH-ready: raw DNS request printout (for server), base64 encoding of hostname parameter in 
  GET/POST (for client)
* pre-emptive HTTP cache population as option (for CDN or local squid/polipo proxies).
  based on Location header, will force the same DNS server software to issue a parallel GET 
  on the remote domain, in order to preemptively populate HTTP caches in between.
  (Not interesting except in particular scenarios, as browsing through high-delay satellite networks).
* added the arduino-ethernet library with the new select() function (sorry for delay, was easy)
* DNSP for HTTP/1 version freeze, development on H2 only (till Hackathon 101 London 17-18/3).

#### Version 1.6 - March 2018:
* sneak peak: REDIS ready _via https://github.com/redis/hiredis_
* more community = more test
* finally fixed infamous proxy settings (not hardcoded they were stopped by mutex leftover).
* removed and commented references to different DNSP modes (threaded/forked, mutex, semaphores).
* finally will update informations to strongly suggest SQUID in place of POLIPO (I loved it, but is EOL)

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
* it really works with millions query
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

## Testing dnsp & HTTP/0.9, 1.0, 1.1

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

## Testing dnsp-h2 with DNS-over-HTTP/2 IETF proposal design

![alt text](https://raw.githubusercontent.com/fantuz/DNSProxy/master/capture-http2.png)

The capture shows an HTTP/2 dialog as seen by wireshark: this is the only way to show a 
valid HTTP/2 capture without having to load certificate and key for MITM dissection.
Obviously a correct negotiation doesn not happen due HTTP v1 URI without Upgrade support
(deactivated in this test anyway) and insecure URI http://www.fantuz.net/nslookup.php

```
max@trinity:~/DNSProxy$ sudo ./dnsp-h2 -w 443 -s http://www.fantuz.net/nslookup.php -C
 *** verbose CURL ON
No HTTP caching proxy configured, continuing without cache
WHAT: 229d9b40 - 41**** ?host=facebook.com.&type=A
 *** HTTP does NOT guarantee against MITM attacks. Consider switching to HTTPS webservice
== 0 Info:   Trying 104.27.132.199...
== 0 Info: TCP_NODELAY set
== 0 Info:   Trying 2400:cb00:2048:1::681b:85c7...
== 0 Info: TCP_NODELAY set
== 0 Info: Immediate connect fail for 2400:cb00:2048:1::681b:85c7: Network is unreachable
== 0 Info:   Trying 2400:cb00:2048:1::681b:84c7...
== 0 Info: TCP_NODELAY set
== 0 Info: Immediate connect fail for 2400:cb00:2048:1::681b:84c7: Network is unreachable
== 0 Info: Connected to www.fantuz.net (104.27.132.199) port 80 (#0)
== 0 Info: Using HTTP2, server supports multi-use
== 0 Info: Connection state changed (HTTP/2 confirmed)
== 0 Info: Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
== 0 Info: Using Stream ID: 1 (easy handle 0x55cfda083a20)
0 => Send header, 170 bytes (0xaa)
0000: GET /nslookup.php?host=facebook.com.&type=A HTTP/2
0034: Host: www.fantuz.net
004a: User-Agent: curl/7.59.0-DEV
0067: Accept: */*
0074: Accept-Encoding: deflate
008e: content-type: text/plain
00a8: 
== 0 Info: http2 error: Remote peer returned unexpected data while we expected SETTINGS frame.  Perhaps, peer does not support HTTP/2 properly.
== 0 Info: Connection #0 to host www.fantuz.net left intact
WHAT: 229d9b40 - 41**** ?host=facebook.com.&type=A
 *** HTTP does NOT guarantee against MITM attacks. Consider switching to HTTPS webservice
== 0 Info:   Trying 104.27.132.199...
== 0 Info: TCP_NODELAY set
== 0 Info:   Trying 2400:cb00:2048:1::681b:85c7...
== 0 Info: TCP_NODELAY set
== 0 Info: Immediate connect fail for 2400:cb00:2048:1::681b:85c7: Network is unreachable
== 0 Info:   Trying 2400:cb00:2048:1::681b:84c7...
== 0 Info: TCP_NODELAY set
== 0 Info: Immediate connect fail for 2400:cb00:2048:1::681b:84c7: Network is unreachable
== 0 Info: Connected to www.fantuz.net (104.27.132.199) port 80 (#0)
== 0 Info: Using HTTP2, server supports multi-use
== 0 Info: Connection state changed (HTTP/2 confirmed)
== 0 Info: Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
== 0 Info: Using Stream ID: 1 (easy handle 0x55cfda06fce0)
0 => Send header, 170 bytes (0xaa)
0000: GET /nslookup.php?host=facebook.com.&type=A HTTP/2
0034: Host: www.fantuz.net
004a: User-Agent: curl/7.59.0-DEV
0067: Accept: */*
0074: Accept-Encoding: deflate
008e: content-type: text/plain
00a8: 
== 0 Info: http2 error: Remote peer returned unexpected data while we expected SETTINGS frame.  Perhaps, peer does not support HTTP/2 properly.
== 0 Info: Connection #0 to host www.fantuz.net left intact

```

![alt text](https://raw.githubusercontent.com/fantuz/DNSProxy/master/capture.jpg)

The capture shows correspondance between expected/produced sent/received DNS packet.
```
max@trinity:~/DNSProxy$ sudo ./dnsp-h2 -s https://php-dns.appspot.com/ -C -v
 *** verbose CURL ON
 *** DEBUG ON
No HTTP caching proxy configured, continuing without cache
WHAT: 46068930 - 41
SIZE OF REQUEST: 41
INFO: transaction 653c - name facebook.com. - size 41 
init lock OK ... 
params->xhostname->hostname		: facebook.com.
params->xdns_req->hostname		: 
xdns_req->hostname			: facebook.com.
VARIABLE sin_addr			: 16777343
VARIABLE sin_addr human-readable	: 127.0.0.1
VARIABLE script				: https://php-dns.appspot.com/
VARIABLE yhostname			: facebook.com.

**** ?host=facebook.com.&type=A
== 0 Info:   Trying 172.217.16.148...
== 0 Info: TCP_NODELAY set
== 0 Info: Connected to php-dns.appspot.com (172.217.16.148) port 443 (#0)
== 0 Info: found 148 certificates in /etc/ssl/certs/ca-certificates.crt
== 0 Info: ALPN, offering h2
== 0 Info: ALPN, offering http/1.1
== 0 Info: SSL connection using TLS1.2 / ECDHE_RSA_CHACHA20_POLY1305
== 0 Info: 	 server certificate verification OK
== 0 Info: 	 server certificate status verification SKIPPED
== 0 Info: 	 common name: *.appspot.com (matched)
== 0 Info: 	 server certificate expiration date OK
== 0 Info: 	 server certificate activation date OK
== 0 Info: 	 certificate public key: RSA
== 0 Info: 	 certificate version: #3
== 0 Info: 	 subject: C=US,ST=California,L=Mountain View,O=Google Inc,CN=*.appspot.com
== 0 Info: 	 start date: Tue, 13 Feb 2018 11:12:07 GMT
== 0 Info: 	 expire date: Tue, 08 May 2018 10:40:00 GMT
== 0 Info: 	 issuer: C=US,O=Google Trust Services,CN=Google Internet Authority G3
== 0 Info: 	 compression: NULL
== 0 Info: ALPN, server accepted to use h2
== 0 Info: Using HTTP2, server supports multi-use
== 0 Info: Connection state changed (HTTP/2 confirmed)
== 0 Info: Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
== 0 Info: Using Stream ID: 1 (easy handle 0x563145a7fa10)
0 => Send header, 163 bytes (0xa3)
0000: GET /?host=facebook.com.&type=A HTTP/2
0028: Host: php-dns.appspot.com
0043: User-Agent: curl/7.59.0-DEV
0060: Accept: */*
006d: Accept-Encoding: deflate
0087: content-type: text/plain
00a1: 
== 0 Info: Connection state changed (MAX_CONCURRENT_STREAMS updated)!
0 <= Recv header, 13 bytes (0xd)
0000: HTTP/2 200 
0 <= Recv header, 26 bytes (0x1a)
0000: content-type: text/plain
0 <= Recv header, 46 bytes (0x2e)
0000: last-modified: Mon, 05 Mar 2018 23:56:52 GMT
0 <= Recv header, 40 bytes (0x28)
0000: etag: 9d0fbea4dc7bb088426ad7a9fc3600f4
0 <= Recv header, 61 bytes (0x3d)
0000: x-cloud-trace-context: b95bf16eb06b625833aa143c172fed0f;o=1
0 <= Recv header, 37 bytes (0x25)
0000: date: Mon, 05 Mar 2018 23:56:52 GMT
0 <= Recv header, 25 bytes (0x19)
0000: server: Google Frontend
0 <= Recv header, 20 bytes (0x14)
0000: content-length: 13
0 <= Recv header, 54 bytes (0x36)
0000: cache-control: public, max-age=14400, s-maxage=14400
0 <= Recv header, 8 bytes (0x8)
0000: age: 0
0 <= Recv header, 151 bytes (0x97)
0000: alt-svc: hq=":443"; ma=2592000; quic=51303431; quic=51303339; qu
0040: ic=51303338; quic=51303337; quic=51303335,quic=":443"; ma=259200
0080: 0; v="41,39,38,37,35"
0 <= Recv header, 2 bytes (0x2)
0000: 
0 <= Recv data, 13 bytes (0xd)
0000: 185.60.216.35
== 0 Info: Connection #0 to host php-dns.appspot.com left intact
[185.60.216.35]
THREAD CURL-CODE			: 0
THREAD CURL-RESULT			: [185.60.216.35]
THREAD-V-ret				: [0]
THREAD-V-type				: 0
THREAD-V-type				: A
THREAD-V-size				: 41
THREAD-V-socket-sockfd			: 3
THREAD-V-socket-xsockfd-u		: 0
THREAD-V-socket-xsockfd-d		: 0
THREAD-V-MODE-ANSWER			: 0
THREAD-V-xclient->sin_addr.s_addr	: 16777343
THREAD-V-xclient->sin_port		: 1494
THREAD-V-xclient->sin_family		: 2
THREAD-V-answer				: [185.60.216.35]

BUILD-yclient->sin_addr.s_addr		: 16777343
BUILD-yclient->sin_port			: 1494
BUILD-yclient->sin_family		: 2
BUILD-xrequestlen			: 41
BUILD-xsockfd				: 0
BUILD-sockfd				: 0
BUILD-hostname				: facebook.com.

INSIDE-raw-datagram			: 
INSIDE-raw-datagram			: 45e54b3e
INSIDE-raw-datagram			: 1172654910
INSIDE-yclient->sin_addr.s_addr        	: 16777343
INSIDE-yclient->sin_port               	: 1494
INSIDE-yclient->sin_port               	: 54789
INSIDE-yclient->sin_family		: 2
INSIDE-dns-req->hostname		: facebook.com.
INSIDE-xrequestlen			: 41

DNS-hex:
45e54b10
0x000000: 65 3c 85 80 00 01 00 01 e<......
0x000008: 00 00 00 00 08 66 61 63 .....fac
0x000010: 65 62 6f 6f 6b 03 63 6f ebook.co
0x000018: 6d 00 00 01 00 01 c0 0c m.......
0x000020: 00 01 00 01 00 00 38 40 ......8@
0x000028: 00 04 b9 3c d8 23 00 00 ...<.#..
0x000030: 00 00 00 00 00 00 00 00 ........
0x000038: 00 00 00 00 00 00 00 00 ........
0x000040: 00 00 00 00 00 00 00 00 ........
0x000048: 00 00 00 00 00 00 00 00 ........
0x000050: 00 00 00 00 00 00 00 00 ........
0x000058: 00 00 00 00 00 00 00 00 ........
0x000060: 00 00 00 00 00 00 00 00 ........
0x000068: 00 00 00 00 00 00 00 00 ........
0x000070: 00 00 00 00 00 00 00 00 ........
0x000078: 00 00 00 00 00 00 00 00 ........
0x000080: 00 00 00 00 00 00 00 00 ........
0x000088: 00 00 00 00 00 00 00 00 ........
0x000090: 00 00 00 00 00 00 00 00 ........
0x000098: 00 00 00 00 00 00 00 00 ........
0x0000a0: 00 00 00 00 00 00 00 00 ........
0x0000a8: 00 00 00 00 00 00 00 00 ........
0x0000b0: 00 00 00 00 00 00 00 00 ........
0x0000b8: 00 00 00 00 00 00 00 00 ........
0x0000c0: 00 00 00 00 00 00 00 00 ........
0x0000c8: 00 00 00 00 00 00 00 00 ........
0x0000d0: 00 00 00 00 00 00 00 00 ........
0x0000d8: 00 00 00 00 00 00 00 00 ........
0x0000e0: 00 00 00 00 00 00 00 00 ........
0x0000e8: 00 00 00 00 00 00 00 00 ........
0x0000f0: 00 00 00 00 00 00 00 00 ........
0x0000f8: 00 00 00 00 00 00 00 00 ........
SENT 46 bytes
unlock NOT OK..
destroy NOT OK..
^C
max@trinity:~/DNSProxy$ 
```

## References:

* https://www.reddit.com/user/fantamix/comments/7yotib/dnsp_a_dns_proxy_to_avoid_dns_leakage/
* https://www.reddit.com/r/hacking/comments/7zjbv2/why_to_use_a_dns_proxy_why_shall_it_be/
* https://tools.ietf.org/html/draft-ietf-dnsop-dns-wireformat-http-01
* https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-03
* https://www.meetup.com/it-IT/Geneva-Legal-Hackers/messages/boards/thread/51438161

## License
MIT license, all rights included.

## Disclaimer
WHEN FULL-ANONIMITY IS A CONCERN, make sure to host *nslookup.php* on a trustable server !

To be clear, the PHP script DOES DO the underlying (infamously leaking) "system call",
the "classic UDP/DNS request" (or TCP but mostly not). Such system call relies on different
mechanisms to resolve DNS, depending on the operating system; in the case of an hosting
provider, such mechanism and operating systems are said to be "managed" hence not in full
control of the user. In the context of hosting, we can probably assume that _everythin_ has
been optimised for serving at the fastest speed with the most of caching made possible.
Such system calls are therefore outside the control of DNSP.

The DNSProxy *DNSP* is just lazily tunneling into HTTP(S) using curllib and nghttp2.
By doing this encapsulation, **it avoids leakage** of UDP queries. To be on the safe side,
using DNS over HTTPS makes eavesdropping and spoofing of DNS traffic between you and the 
HTTPS provider much less likely.

That said, you **MUST** use an external server that you trust and you can deploy stuff on !
**Do not forget to set 127.0.0.1 as your unique system resolver (/etc/resolv.conf)**.

Beware, having the PHP script running on the same local machine (not using a remote webservice)
makes no sense and WILL make ALL of your DNS queries leaking. Useful for TESTING purposes only !!
