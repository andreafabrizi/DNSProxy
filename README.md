# DNS-over-HTTPS Proxy

## Why DNSP ?
A new idea in terms of transport of DNS messaging, outside of its original design!
DNS-over-HTTP has been published as RFC (c.f. 
https://www.rfc-editor.org/rfc/rfc8484.txt, https://tools.ietf.org/html/rfc8484).
A new MIME type has been defined (application/dns-message) and design goals are
perfectly clear.

All my Coding efforts -collected in this repository- aimed to support the deploy
of **DoH client** as rudimental system-resolver.

DNSP software supports 3 different variations of DoH basic format, being:
 - **application/dns-message [RFC8484]**: RFC8484-compliant - newest pure DoH format
 - **application/dns+json    [RFC8427]**: JSON format - legacy
 - **application/dns         [RFC4027]**: text/data format - obsolete

For more information about MIME types, refer to IANA website: https://www.iana.org/assignments/media-types/media-types.xhtml

## How does it work ?
DNS proxy listens for incoming DNS requests (A,NS,MX,TXT,SRV..) on both
UDP & TCP. Threads listen for incoming connections; when a query comes in,
DNSP parses DNS query contents and starts forwarding such queries to a DoH
service provider (DoH HTTP server) which in turn deals with the real DNS resolution.

Exchange of messaging happens by means of standardized HTTP request & response,
with the help of headers, either towards an external PHP script or a DoH public
webservice.

DoH and DNSP leverage the fancyness of HTTP and TLS, hence are easy to debug and monitor.

## Build

DNSP will take care to create a well-formed UDP/TCP packet as reply to the client.

The core PHP-script can be hosted anywhere, i.e. on Google Cloud Platform.

Should you be willing to perform "response caching and sharing" you can rely 
on your favourite HTTP/HTTPS proxy server, as any of polipo, squid, nginx, 
Varnish, charles, SOCKS, TOR, *any HTTP proxy* will work properly with DNSP.

DNSP can be configured to cross through (and receiving Via) additional HTTP 
proxy (i.e. TOR, enterprise-proxy, locked-down countries).

Most of users will run DNSP directly through HTTPS w/out caching & extra proxy.
The DNSP server will just talk to remote resolver webservice, w/out any cache.

As we all know, "a cache" is often availaible "in the network" when it comes to
HTTP, no real need for extra local cache (HTTP/2 and HTTPS make local cache uneasy).

If you can't access "secured" VPN tunnels to resolve names externally (i.e.
TOR users, Chinese walls), DNSProxy is a rapid and efficient solution for you.

As bonus, this software is TOR-friendly and requires minimal resources. Enjoy !

## Architecture
```
              +---------------------------+
   +----------| DNSP listens on original  | <<--+
   |          | sockets [ HTTP(S) & DNS ] |     |
   |          +---------------------------+     | libCURL handles
   |                    ^                       | HTTP(S) replies.
   |                    ^  IF answer found      | DNSP creates DNS
   |                    |   in HTTP cache       | responses, sent
   |                    |  THEN faster reply    | via TCP or UDP
   v                    |  and same security    | as per RFC 1035.
   v                    :                       :
  +-------------+     +--------+--------+     /---------------\
  |client OS    |-->> +    DNSProxy     +-->> |  DoH resolver |
  +-------------|     +-----------------+     |   webservice  |
  |sends DNS    |     | manipulate TTL, |     | RFC8484-aware |
  |to nameserver|     | blacklist,cache |     \---------------/
  +---+---------+     +-----------------+                ^
     :                                                   ^
     | UDP & TCP queries to DNSP daemon on 127.0.0.1:53  |
     |       are tunneled to a DoH-resolver webservice   |
     +---------------------------------------------------+

 classic DNS except that messages are being transported over HTTP/2
      with no leackage of UDP whatsoever (see PRIVACY notes)
```

Features:
- DNS-over-HTTPS compliant with RFC 8484, plus older non-standards supported.
- FOLLOWLOCATION, spawns threads to enable HTTP browser cache preemption
    for the benefit of the user experience.
- HTTP/2 ready. Talks HTTP/2 in different combinations of ALPN, NPN, Update & co.
- as HTTP/2 is the minimum requirement for DOH (see RFC 8484), to comply is easy
    using libCURL, lesser with nghttp2,
- ability to dump DNS response packet, then serve such content via local HTTP webserver
    (not in DNSP intents, but possible for the benefit and simplicity of DOH adoption !)
- ability to set specific headers according to cache requirements,
    i.e. translate DNS TTL validity to HTTP cache Validity :)

To recap, in order to start resolving "anonymous DNS" over HTTP, all you need is:
- a PHP-server hosting the *nslookup-doh.php* resolver script
- the C software, available as source or compiled

## Caching answers in the network

DNS cache is populated with standard HTTP answers provided by the remote webservice 
(which in turn uses headers from nslookup-doh.php to influence such caching accordingly).
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
```
NB: Some parts of this "distributed cache" might be held on a CDN for a transient period.
An intermediate cache layer is often present nowadays, unless forbidden by headers or expiry.
Headers are your friends.

**IMPORTANT:** Please, don't use the script hosted on my server(s) as they serve as demo-only.
They might be subject to unpredicted change, offlining, defacing.... Trust your own servers, and 
host yourself as many *nslookup-doh.php* scripts as you can, or send it on a friend's server!

The more DNSP resolvers around the world, the less DNS queries will be traceable (TOR leaking problem).

```bash
 dnsp-h2 2.5, copyright 2010-2019 @ Massimiliano Fantuzzi HB9GUS, MIT License

 usage: dnsp-h2 [-l <local_host_address>] [-p <local_port>] [-H <proxy_host>]
	[-r <proxy_port>] [-w <lookup_port>]
	-s <HTTP_URL_of_DOH-DNS_lookup_script_or_resolving_service>

 OPTIONS:
  [ -l <IP/FQDN> ]	 Local server address
  [ -p <53>      ]	 Local server port, defaults to 53
  [ -H <IP/FQDN> ]	 Cache proxy address
  [ -r <3128>    ]	 Cache proxy port
  [ -u <user>    ]	 Cache proxy username
  [ -k <pass>    ]	 Cache proxy password
  [ -w <443>     ]	 Lookup port
  [ -Q           ]	 Use TTL from CURL, suggested
    -s <URL>      	 Lookup script URL

 EXPERT OPTIONS:
  [ -T <n> ]	 Override TTL [0-2147483647] defined in RFC2181
  [ -Z <n> ]	 Override TCP response size to be any 2 bytes at choice
  [ -n     ]	 Enable DNS raw dump
  [ -v     ]	 Enable debug
  [ -X     ]	 Enable EXTRA debug
  [ -R     ]	 Enable THREADS debug
  [ -L     ]	 Enable LOCKS debug
  [ -N     ]	 Enable COUNTERS debug
  [ -C     ]	 Enable CURL debug, useful to debug cache, certs, TLS, etc

 TESTING/DISABLED OPTIONS:
  [ -I     ]	 Upgrade Insecure Requests, debug HSTS, work in progress
  [ -R     ]	 Enable CURL resolve mechanism, avoiding extra gethostbyname
  [ -t <n> ]	 Stack size in format 0x1000000 (MB)

 Example with direct HTTPS:
	./dnsp-h2 -s https://php-dns.appspot.com/
 Example with direct HTTP:
	./dnsp-h2 -s http://www.fantuz.net/nslookup.php
 Example with HTTP caching proxy:
	./dnsp-h2 -r 8118 -H http://your.proxy.com/ -s http://www.fantuz.net/nslookup.php
 Further tests:
	./dnsp-h2 -T 86400 -v -X -C -n -s https://php-dns.appspot.com/ 2>&1

 For a more inclusive list of DoH providers, clients, servers and protocol details, see:
 - https://en.wikipedia.org/wiki/Public_recursive_name_server
 - https://sslretail.com/blog/dns-over-https-ultimate-guide/
 - https://github.com/curl/curl/wiki/DNS-over-HTTPS
 - https://tools.ietf.org/html/rfc8484

```

## Building

Build is easy on Linux, Mac... UNIX and Windows.
Based on CURL C library, pthread, SSL/TLS and various other strong standards.
A recent version of CURL is needed to leverage HTTP/2 capabilities (nghttp2).

`apt-get install libcurl4-openssl-dev curl libsslcommon2-dev \
libssl-dev ca-certs brotli gnutls-bin openssl libtlsh-dev`

Once done with installing such pre-requisites, compile with:
`make`

## Installing

#### STEP 1. Create and deploy the HTTP(S) nameserver webservice
Deploy **nslookup-doh.php** on a webserver, possibly not your local machine (see DISCLAIMER).
If you ignore how-to carry on such deploy task or you do not have access to any of
such webservers, just use my own webservice, as suggested in usage examples.

#### STEP2 2, Have access to an HTTP(S) proxy, optional but preferable
Setup an HTTP caching proxy on the local machine or on a remote host. Feed host and
port of your proxy server to the *dnsp* program arguments.

#### STEP 3: compile DNSP binary
Compile the *dnsp* binary by running provided build commands (make, for example)

## Integration, easy with standards:

DNSP has been build keeping in mind _simplicity_ and _standardness_.
Most of us will know that -on a modern Linux box- an extra layer of
caching DNS  is provided by nscd or dnsmasq services. Even in presence
of such caches, UDP+TCP DNS traffic accounts today for a sensible and
quite constant bandwidth consumption.

DNSP is _not_ an alternative to such caching services. They can coexist
when needed. In a way, DNS can be integrated to work closely with new
**DNS services** in empowering a more distributed cache, or might be
dropping the HTTP cache as a whole, in favour of clever methods of doing
the same operation: distribute DNS by means of standardised HTTP methods.

In a scenario dominated by CDN, anycasting and load balancing, the HTTP
(insecure) cache is becoming less and less effective due to the added
security layers and increasing speed between peers (hence the lack of
the need of an HTTP proxy). It will be worth looking at QUIC, the
UDP-multiplexing upcoming HTTP/3 standard.

As the whole internet has been - a **standardised work in progress** in
the past 40 years - so DNSP is: experimental software, a community tool.

DNSP presents itself as an alternative transport method of the good old
and fascinating DNS. As I often stated, DNSP was conceived as a way to
help overcome censorship and trackability via DNS. As you might question
yourself -YES- any **DNS-over-HTTP** will leave a trace, just that trace
will be in a different place, not on UDP level but eventually onto some
HTTP webserver logs on a remote server.

I never meant to state that DNSP is faster or better than any other DNS
server, but is definitely original on its own. Is a really ugly piece of
single-threaded code made to help people _transporting_ and _sharing_ DNS.

## Testing dnsp & dnsp-h2

Simply run one of the two available programs as follows.

To start a pre-h2 pre-DoH (HTTP/1.1) DNSProxy server, type:
```bash
dnsp -l 127.0.0.1 -s https://www.fantuz.net/nslookup.php
```
If you prefer to run an HTTP2-compliant server (as per DoH's RFC 8484), type:
```bash
dnsp-h2 -l 127.0.0.1 -s https://www.fantuz.net/nslookup-doh.php
```
Note that dnsp (the pre-DOH version of DNSProxy) is kept only for backwards compatibility and may
disappear at any time. Please use only dnsp-h2 by default. Eventually push commits into the latter one.

At this point, you might want to start your traffic capture, either wireshark, tshark or tcpdump.

Now open a new terminal and invoke **dig** (or **nslookup**) to resolve a sample hostname against
our brand-new server instance of DNSP:

Type the following command to test UDP listener:
```bash
dig news.google.com @127.0.0.1
```
The result shall correspond to this output, no errors or warning shall be trown.
```
; <<>> DiG 9.10.3-P4-Ubuntu <<>> news.google.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 17828
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;news.google.com.       IN  A

;; ANSWER SECTION:
news.google.com.    524549  IN  A   216.58.206.142

;; Query time: 303 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Tue Jan 29 21:00:49 CET 2019
;; MSG SIZE  rcvd: 49
```
A similar command is to be run order to test TCP listener:
```bash
dig +tcp facebook.com @127.0.0.1
```
Again, resulrs should correspond to the following output.

```
; <<>> DiG 9.10.3-P4-Ubuntu <<>> +tcp facebook.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9475
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;facebook.com.          IN  A

;; ANSWER SECTION:
facebook.com.       524549  IN  A   185.60.216.35

;; Query time: 277 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Tue Jan 29 21:00:50 CET 2019
;; MSG SIZE  rcvd: 46
```

If queries are successful, you can now safely replace the current
"nameserver" entries inside "/etc/resolv.conf" to point ALL DNS
traffic towards DNSP, by inserting such a line:
```
nameserver 127.0.0.1
```

Once configuration and testing completed successfully, you will be
ready to run a DNS-over-HTTPS peer & server as described by RFC 8484.

To test if DNSProxy is working fine you can run a simple traffic 
capture with wireshark/tcpdump, checking for DNS messages integrity
using integrated dissectors.

## Testing deploy of PHP script

To test the deploy of nslookup-doh.php along with correct DNS
resolution, you could use **curl** utility within a shell.
Replace URL value in accordance with your favourite script location.
Here are two simple one-liners that I use to check my deploys:
```
# curl -s -H "Host: www.fantuz.net" -H "Remote Address:104.27.133.199:80" -H "User-Agent:Mozilla/5.0 \
(Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 \
Safari/537.36" 'http://www.fantuz.net/nslookup-doh.php?host=fantuz.net&type=NS' | xxd

# curl -s -H "Host: php-dns.appspot.com" -H "User-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36" \
'http://php-dns.appspot.com/helloworld.php?host=fantuz.net&type=NS' | xxd
```

Values should end with bits 0d0a. on any server (HEX is easy to read):
```
00000000: 7364 6e73 332e 7668 6f73 7469 6e67 2d69  sdns3.vhosting-i
00000010: 742e 636f 6d0d 0a                        t.com..
```

## Testing dnsp-h2 with DNS-over-HTTPS, RFC 8484

![alt text](https://raw.githubusercontent.com/fantuz/DNSProxy/master/capture-http2.png)

The capture shows an HTTP/2 dialog as seen by wireshark: this is the only way to show a 
valid HTTP/2 capture without having to load certificate and key for MITM dissection.
Obviously a correct negotiation doesn not happen due HTTP v1 URI without Upgrade support
(deactivated in this test anyway) and insecure URI http://www.fantuz.net/nslookup-doh.php

```
max@trinity:~/DNSProxy$ sudo ./dnsp-h2 -w 443 -s http://www.fantuz.net/nslookup-doh.php -C
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
0x000028: 00 04 b9 3c d8 23       ...<.#
SENT 46 bytes
unlock NOT OK..
destroy NOT OK..
^C
max@trinity:~/DNSProxy$ 
```

## Changelog:

#### Version 2.5 - February 2019:
* provide base64urlencode of DNS requests !
* implemented dump of "cache-control" headers from PHP/DoH resolver into DNS packet
* added new build_dns to comply with DoH/RFC format, instead of old build_dns_response
* account for TRANSACTION-ID override (0xabcd by default)
* account for TYPE override (0x00 by default)
* make sure we set accept & content-type to "application/dns" for both POST and GET

#### Version 2.2 - January 2019:
* completed TCP & UDP listeners

#### Version 2 - March 2018:
* Added TCP query/response support !
* backend DOH-ready: raw DNS request printout (for server), base64urlencode of DNS query (for client)
* pre-emptive HTTP cache population as option (for CDN or local squid/polipo proxies).
  based on Location header, will force DNSP server software to issue a parallel GET towards
  the remote domain, in order to preemptively populate HTTP local and intermediate caches.
  (Not very interesting except in few scenarios, as surfing through high-delay networks).
* added the arduino+ethernet library with the new select() function [sorry for delay]
* DNSP for HTTP/1 version freeze, development on H2 only (till Hackathon 101 London 17-18/3).

#### Version 1.6 - March 2018:
* almost REDIS-ready _via https://github.com/redis/hiredis_
* finally fixed "infamous" proxy settings
* removed and commented references to different DNSP modes (threaded/forked, mutex, semaphores).
* finally updated examples to strongly suggest SQUID in place of POLIPO (I loved it, but is EOL)

#### Version 1.5 - February 2018:
* added IETF references and mentions to DoH (wich is based on HTTP/2, single connection multiple streams)
* added Arduino double ethernet shield script
* fixed NS/CNAME answers (C) and resolver script (PHP)
* added the GO version made by chinese people, inspired at my DNSP software
* MIT License in accordance to transfer of rights operated via mail by Andrea
* everything works as usual: caching is lazy, CURL follows redirects (301, I want less of them)
* other thought and implementations pending
* fixed README and easen installation/testing procedure
* deleted some junk files, renamed dirs for clarity
* multiversion PHP 5/7, depending on hosting provider (due to slightly different
    implementation of print(), random css, substantial differences between h1/h2, headers, etc).

#### Version 1.01 - March 2017:
* going back to either threads or vfork...
* having few issues caching on ClouFlare-alike caches (304 no-more ?). Probably fault of Etag
* more crash-test, memory-leak hunting, strace & timing tests
* works with millions query [not anymore since I added TCP]
* published an improved Varnish configuration

#### Version 1.01 - April 2015:
* HTTPS support (even more privacy)
* Pseudo-Multithreading listener/responder
* Better nginx/polipo setup ? [ not anymore useful with HTTP/2 ]
* Stack size option (deprecated)
* Soon to add TCP listener/responder logic
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

## WIP - features being actively worked on:
* offer GET & POST choice on method (for all DoH and pre-DoH URLs). So far, only GET is supported.
* save HEX packet structure, to serve it as HTTP content from DNSP daemon or prime the local disk cache
* support far more than A, AAAA, CNAME and NS. My pre-DoH test protocol supported MX, PTR and ALL types
* add a "--resolve" option to pin DoH request to an IP address (see SNI debate)
* find out why some requests encounter ";; Question section mismatch: got fantuz.net/RESERVED0/IN"
* reduce memory impact (following TCP listener implementation, memory footprint is out of control)
* test build on Debian, Windows, MacOS (only tested with Ubuntu 14-18 and very old MacOS)
* test bynary distribution on Debian, Windows, MacOS
* add switch to leverage REUSEPORT and/or REUSEADDRESS

## Ideas - lower priority:
* implement HTTP/2 PUSH, for smoother and opportunistic DNS answers. Remember, there's no ID field in DOH !
* use h2 "Warning" headers to signal events/failures
* to use NGHTTP2 in place of CURL. A faster way to support H2 (anyways, CURL requires NGHTTP2)
* parallelize requests, choose the faster response
* restore performances, currently impacted by new TCP handlers
* REDIS: implement or let die
* DNSSEC validation tests ?
* add a statistics backend

## Non-inclusive DoH providers list
* 1.1.1.1
* 8.8.8.8
* 9.9.9.9
* see list on https://github.com/curl/curl/wiki/DNS-over-HTTPS#publicly-available-servers

## References:

* https://datatracker.ietf.org/meeting/101/materials/slides-101-hackathon-sessa-dnsproxy-local-dns-over-http-private-resolver
* https://igit.github.io/
* https://www.reddit.com/user/fantamix/comments/7yotib/dnsp_a_dns_proxy_to_avoid_dns_leakage/
* https://www.reddit.com/r/hacking/comments/7zjbv2/why_to_use_a_dns_proxy_why_shall_it_be/
* https://github.com/curl/doh/blob/master/doh.c
* https://www.meetup.com/it-IT/Geneva-Legal-Hackers/messages/boards/thread/51438161
* https://tools.ietf.org/html/draft-ietf-dnsop-dns-wireformat-http-01
* https://tools.ietf.org/html/rfc8484

## License
MIT license, all rights included.

## Disclaimer
__IF ANONIMITY IS A CONCERN__ please host *nslookup-doh.php* on a trusted server !

To be clear, the PHP script DOES DO the underlying job, being the resolution
via "system calls" of DNS requests, a "classic" UDP or TCP "DNS request".
Such system call relies on different (leaking) mechanisms to resolve DNS,
depending on the operating system; in the case of an hosting provider, such
mechanism and operating systems are often "managed" hence not in FULL-CONTROL
of the final user.

In the context of "managed-hosting" we can probably assume that _everything_
had been optimised for serving contents at the fastest speed, leveraging the
best cache available.

Performances of such sys-calls lie therefore outside the scope of DNSP.

The DNSProxy *DNSP* is just lazily tunneling into HTTP(S) using curllib and
nghttp2. By doing this encapsulation, **it avoids leakage** of UDP queries.
To be on the safe side, using DNS-over-HTTPS makes almost impossible to
eavesdrop and spoof the DNS traffic between you and the DoH provider, or
at least much less likely, given the layer of security provided by HTTP/2.

That said, you **MUST** use an external resolver/server that you trust, one
where you can deploy stuff !

**Do not forget to set 127.0.0.1 as your unique system DNS resolver** via
common system configuration files (as /etc/resolv.conf or systemd-resolved).

Beware: running the PHP script locally on the same machine (not using a
remote webservice) makes no sense and WILL EXPOSE ALL of your queries to
DNS leak. Running locally is useful for TESTING purposes only !!

