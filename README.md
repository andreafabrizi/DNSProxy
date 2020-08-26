# DNS-over-HTTPS Proxy - Overview

## Why DNSP ?
#DNS messaging transport tests, gone too far.

DNSP was born for two reasons: deliver DNS responses to airplanes, and surf TOR anonymously.

About the first: DNS UDP messages were lost onto satellite pipe, hence I needed to invent a new
trasnport and caching protocol to transport the very same information. I chose to shift to HTTP
and leveragge caching onto Polipo/Squid proxy. DNS client used a 127.0.0.1 server, to vehiculate
such traffic in and out HTTP and DNS.

The second came before the first actually ... UDP and DNS were not completely socks friendly, and
not even TOR-compatible. The one and only choice left was to vehiculate DNS messages INSIDE a
protocol that could be well-protected and easily-ecapsulated within TOR.

That protocol was -obviously and again- HTTP, in it's most secure version, the S version (HTTPS).

That many many tests (since 2010) got a bit out of control, up to the point that I was invited to
collaborate with IETF to the developement of the state-of-the-art DNS-over-HTTPS, aka RFC8484.

DNS-over-HTTP has been published end 2018 as RFC (c.f. 
https://www.rfc-editor.org/rfc/rfc8484.txt, https://tools.ietf.org/html/rfc8484).

A new MIME type has been defined (application/dns-message) and design goals are
perfectly clear.

All my coding/testing efforts -collected in this repository- aimed to support the deploy
of **DoH client** as rudimental system-resolver, now fully independent.

You can run a server without havin ANY access to UDP or port 53. Everything will go via HTTP/2
using port 443, for the time being. Further developement towards QUIC/HTTP/3 support is WIP.

DNSP software used to support 3 different variations of unoficcial-DoH formats, being:
 - **application/dns-message [RFC8484]**: RFC8484-compliant - newest pure DoH format
 - **application/dns+json    [RFC8427]**: JSON format - legacy
 - **application/dns         [RFC4027]**: text/data format - obsolete

It now supports just and only the first format, the official RFC8484 standard format.

For more information about MIME types, refer to IANA website: https://www.iana.org/assignments/media-types/media-types.xhtml

## How does it work ?
DNS proxy listens for incoming DNS requests (A,NS,MX,TXT,SRV..) on both
UDP & TCP.

Threads listen for incoming connections; when a query comes in,
DNSP parses DNS query contents and starts forwarding such queries to a DoH
service provider (DoH server) which in turn deals with the real DNS resolution.

Exchange of messaging happens by means of standardized HTTP request & response,
with the help of HTTP headers.

DoH and DNSP leverage the fancyness of HTTP and TLS, therefore are quite easy
when it come to debug and monitor.

If you can't access "secured" VPN tunnels to resolve names externally (i.e.
TOR users, Chinese walls), DNSProxy is a rapid and efficient solution for you.

## Architecture
```
              +----------------------------+
   +----------| DNSP listens on original   | <<---+
   |          | sockets [ HTTP(S) & DNS ]  |      |
   |          +----------------------------+      | libCURL handles
   |                      ^                       | HTTP(S) replies.
   |                      ^ IF answer found       | DNSP creates DNS
   |                      |  in HTTP cache        | responses, sent
   |                      | THEN faster reply     | via TCP or UDP
   v                      |  same security        | as per RFC-1035
   v                      :                       :
  +--------------+      +--------+--------+      /---------------\
  |  client OS   | -->> +     DNSProxy    + -->> |  DoH resolver |
  +--------------|      +-----------------+      |   webservice  |
  | sends DNS    |      | manipulate TTL, |      | RFC8484-aware |
  | to nameserver|      | blacklist,cache |      \---------------/
  +--+-----------+      +-----------------+               ^
     :                                                   ^
     | UDP & TCP queries to DNSP daemon on 127.0.0.1:53  |
     |       are tunneled to a DoH-resolver webservice   |
     +---------------------------------------------------+

 classic DNS except that messages are being transported over HTTP/2
      with no leackage of UDP whatsoever (see PRIVACY notes)
```

DNSP will take care to create a well-formed UDP/TCP packet in reply to clients.

Should you be willing to perform "response caching and sharing" you can rely 
on your favourite HTTPS proxy, any between polipo, squid, nginx, Varnish, 
charles, SOCKS, TOR, *any HTTP(S) proxy* will work properly with DNSP.

DNSP can be configured to cross through (and receiving Via) additional HTTP 
proxy (i.e. TOR, enterprise-proxy, locked-down countries).

Most of users will run DNSP directly through HTTPS w/out caching & extra proxy.
The DNSP server will just talk to remote resolver webservice, w/out any cache.

As we all know, "a cache" is often availaible "in the network" when it comes to
HTTP, no real need for extra local cache (HTTP/2 and HTTPS make local cache uneasy).

As bonus, this software is TOR-friendly and requires minimal resources. Enjoy !

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

#### Just use standard Google + Cloudflare DoH servers. Suurf anonymously without HTTP cache (simplest mode):
```bash
dnsp-h2 -Q
```
NB: Some parts of this "distributed cache" might be held on a CDN for a transient period.
An intermediate cache layer is often present nowadays, unless forbidden by headers or expiry.
Headers are your friends.

#### Leverage the use of local HTTP caching proxy. Option "-H" to specify proxy's URI (URI!=URL)
```bash
dnsp -H http://192.168.3.93/ -r 8118
dnsp -H http://aremoteproxyservice/ -r 3128
```

**IMPORTANT:** Please, don't use the script hosted on my server(s) as they serve as demo-only.
They might be subject to unpredicted change, offlining, defacing.... Trust your own servers, and 
host yourself as many *nslookup-doh.php* scripts as you can, or send it on a friend's server!

The more DNSP resolvers around the world, the less DNS queries will be traceable (TOR leaking problem).

# Using DNSP

```bash
user@machine:~/DNSProxy$ ./dnsp-h2

 dnsp-h2 v3.14, copyright 2010-2020 Massimiliano Fantuzzi HB3YOE/HB9GUS, MIT License

 usage: dnsp-h2 [-l <local_host_address>] [-p <local_port>] [-H <proxy_host>]
	[-r <proxy_port>] [ -s <DNS_lookup_resolving_service_URL> ] [-w <lookup_port>]

 OPTIONS:
  [ -Q           ]	 Use TTL from CURL, suggested
  [ -l <IP/FQDN> ]	 Local server address, defaults to all active interfaces
  [ -p <53>      ]	 Local server port, defaults to 53
  [ -H <IP/FQDN> ]	 Cache proxy address (HTTPS-capable)
  [ -r <3128>    ]	 Cache proxy port
  [ -u <user>    ]	 Cache proxy username
  [ -k <pass>    ]	 Cache proxy password
  [ -w <443>     ]	 Lookup port
  [ -s <URL>     ]	 Lookup script URL (deprecated, only for dnsp-v1 and old RFCs)

 ADVANCED OPTIONS:
  [ -T <n> ]	 Override TTL [0-2147483647] defined in RFC2181
  [ -Z <n> ]	 Override TCP response size to be any 2 bytes at choice

  [ -v     ]	 Enable debug
  [ -n     ]	 Enable DNS raw dump
  [ -X     ]	 Enable EXTRA debug
  [ -R     ]	 Enable THREADS debug
  [ -L     ]	 Enable LOCKS debug
  [ -N     ]	 Enable COUNTERS debug
  [ -C     ]	 Enable CURL debug

 EXPERT OPTIONS:
  [ -r     ]	 Enable CURL resolve mechanism, avoiding extra gethostbyname
  [ -t <n> ]	 Stack size in format 0x1000000 (MB)


 For a more inclusive list of DoH providers, clients, servers and protocol details, see:
 - https://tools.ietf.org/html/rfc8484
 - https://github.com/curl/curl/wiki/DNS-over-HTTPS
 - https://it.wikipedia.org/wiki/DNS_over_HTTPS#cite_note-8
```

## Building and Installing

Build is easy on Linux, Mac, UNIX and probably even Windows; DNSProxy is based
on CURL C library, pthread, SSL/TLS and various other strong standards.
A recent version of CURL is needed to leverage HTTP/2 capabilities (aka nghttp2).

```bash
sudo apt-get install libcurl4-openssl-dev curl libsslcommon2-dev \
libssl-dev ca-certs brotli gnutls-bin openssl libtlsh-dev
```
```bash
git clone https://github.com/clibs/clib.git /tmp/clib
cd /tmp/clib
sudo make install
```
```bash
sudo clib install littlstar/b64.c
```

```bash
sudo clib install jwerle/libok
```
Once done with pre-requisites, you will be able to *compile* by running:
```bash
make
```

## Deploy pre-DoH non-standard infrastructure (only applies to dnsp legacy binary, not to dnsp-h2)

#### STEP 1. Create and deploy the HTTP(S) nameserver webservice
Deploy **nslookup-doh.php** on a webserver, possibly not your local machine (see DISCLAIMER).
If you ignore how-to carry on such deploy task or you do not have access to any of
such webservers, just use my own webservice, as suggested in usage examples.

#### STEP2 2, Have access to an HTTP(S) proxy, optional but preferable
Setup an HTTP caching proxy on the local machine or on a remote host. Feed host and
port of your proxy server to the *dnsp* program arguments.

NB: cache is much more difficult in an h2/TLS context, hence cache is not a feature in dnsp-h2

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

## Launching an instance of dnsp or dnsp-h2

Simply run one of the two available programs as follows.

To start a pre-h2 pre-DoH (HTTP/1.1) DNSProxy server, type:
```bash
dnsp -l 127.0.0.1 -s https://www.fantuz.net/nslookup-doh.php
```
Run a fully-compliant DoH/HTTP2 server (as per DoH's RFC 8484), type:
```bash
dnsp-h2
```
NB: you might need to stop other daemons bound to 127.0.0.1:53, as:
dsndist,bind,resolvconf,systemd-resolvconf, and other DNS servers/proxies

Note that dnsp (the pre-DOH version of DNSProxy) is kept only for backwards compatibility and may
disappear at any time. Please use only dnsp-h2 by default. Eventually push commits into the latter one.

At this point, you might want to start your traffic capture, either wireshark, tshark or tcpdump.

Now open a new terminal and invoke **dig** (or **nslookup**) to test the resolver capabilities
over UDP or TCP. The test consist in resolving an hostname against the server instance of DNSP,

To test the UDP listener, type the following:
```bash
dig news.google.com @127.0.0.1
```
The result shall correspond to this output, no errors or warning shall be trown.
```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 17828
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;news.google.com.       IN  A

;; ANSWER SECTION:
news.google.com.    524549  IN  A   216.58.206.142

;; SERVER: 127.0.0.1#53(127.0.0.1)
;; MSG SIZE  rcvd: 49
```
To test the TCP listener, type:
```bash
dig +tcp facebook.com @127.0.0.1
```
Again, results should be similar to the quoted output.

```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9475
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;facebook.com.          IN  A

;; ANSWER SECTION:
facebook.com.       524549  IN  A   185.60.216.35

;; SERVER: 127.0.0.1#53(127.0.0.1)
;; MSG SIZE  rcvd: 46
```

Once all listeners have been tested, you can safely replace the actual
entries inside "/etc/resolv.conf" to point ALL DNS traffic towards DNSP.
Inserting the following line and delete all other "namaserver" entries:
```
nameserver 127.0.0.1
```

NB: in case you use systemd-resolved, you would need to edit the proper
systemd service file at /etc/systemd/resolved.conf or similar.

Once configuration and testing successful, you will be ready to run a
DNS-over-HTTPS client & server as described by RFC 8484.

To test if DNSProxy is working fine you can also run a traffic capture
with tools like wireshark or tcpdump, checking the integrity of DNS messages
using integrated dissectors.

## Testing deployment of PHP script over the web

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


# Versioning and wvolution of DNSP

## Changelog:

#### Version 3.0 - August 2020:
* fixed TCP listener !
* perfect parsing of HTTP reply
* as always, correct encapsulation of response message

#### Version 2.5 - February 2019:
* having segdumps, no good. adding extra debug on CURL status, suspecting a 400 response
* testing further TCP and UDP responses

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
* save HEX packet structure and serve it as HTTP content from DNSP daemon priming the local cache
* support far more than A, AAAA, CNAME and NS. My pre-DoH test protocol supported MX, PTR and ALL types
* add a "--resolve" option to pin DoH request to an IP address (see SNI debate on IETF mailing lists)
* add switch to drive the contruction of DoH vs non-DoH packets
* find out why some requests encounter ";; Question section mismatch: got fantuz.net/RESERVED0/IN"
* reduce memory impact (following TCP listener implementation, memory footprint is out of control)
* test build on Debian, Windows, MacOS (only tested with Ubuntu 14-18 and very old MacOS)
* test bynary distribution on Debian, Windows, MacOS
* add an option to provide dynamic list of blacklisted domains (to be read in from file or STDIN)
* add choiche of http2 options, ALPN, NPN, PRIOR_KNOWLEDGE, etc.
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

* https://tools.ietf.org/html/rfc8484
* https://datatracker.ietf.org/meeting/101/materials/slides-101-hackathon-sessa-dnsproxy-local-dns-over-http-private-resolver
* https://www.reddit.com/user/fantamix/comments/7yotib/dnsp_a_dns_proxy_to_avoid_dns_leakage/
* https://www.reddit.com/r/hacking/comments/7zjbv2/why_to_use_a_dns_proxy_why_shall_it_be/
* https://github.com/curl/doh/blob/master/doh.c
* https://www.meetup.com/it-IT/Geneva-Legal-Hackers/messages/boards/thread/51438161
* https://tools.ietf.org/html/draft-ietf-dnsop-dns-wireformat-http-01
* https://igit.github.io/

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


# Extra useful informations

## Appendix A - Headers and common used Proxies

```

Common proxy ports: 
  1080 (generic proxy) 
  3128 (squid) 
  8118 (polipo) 
  8888 (simplehttp2server) 
  9500 (tor) 
  1090 (socks) 

#echo | openssl s_client -showcerts -servername php-dns.appspot.com -connect php-dns.appspot.com:443 2>/dev/null | openssl x509 -inform pem -noout -text

#curl --http2 -I 'https://www.fantuz.net/nslookup.php?name=google.it'
HTTP/2 200 
date: Sat, 03 Mar 2018 16:30:13 GMT
content-type: text/plain;charset=UTF-8
set-cookie: __cfduid=dd36f3fb91aace1498c03123e646712001520094612; expires=Sun, 03-Mar-19 16:30:12 GMT; path=/; domain=.fantuz.net; HttpOnly
x-powered-by: PHP/7.1.12
cache-control: public, max-age=14400, s-maxage=14400
last-modified: Sat, 03 Mar 2018 16:30:13 GMT
etag: 352d3e68703dce365ec4cda53f420f4a
accept-ranges: bytes
x-powered-by: PleskLin
alt-svc: quic=":443"; ma=2592000; v="35,37,38,39"
x-turbo-charged-by: LiteSpeed
expect-ct: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"
server: cloudflare
cf-ray: 3f5d7c83180326a2-FRA

POST 
echo -n 'q80BIAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | base64 -d 2>/dev/null | curl -H 'content-type: application/dns-message' --data-binary @- https://cloudflare-dns.com/dns-query -o - | hexdump 
 
GET 
curl -H 'accept: application/dns-message' -v 'https://cloudflare-dns.com/dns-query?dns=q80BIAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | hexdump 
 
curl -o - 'https://cloudflare-dns.com/dns-query?dns=q80BIAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB' -H 'authority: cloudflare-dns.com' \ 
-H 'upgrade-insecure-requests: 1' \ 
-H 'user-agent: curl 7.64.1-DEV (x86_64-pc-linux-gnu) libcurl/7.64.1-DEV OpenSSL/1.0.2g zlib/1.2.11 nghttp2/1.37.0-DEV' \ 
-H 'accept: application/dns-message' -H 'accept-encoding: gzip, deflate, br' -H 'accept-language: en-US,en;q=0.9' --compressed | xxd 
 
echo -n 'q80BAAABAAAAAAAABmdpdGh1YgNjb20AAAEAAQ' | base64 -d 2>/dev/null | curl -s -H 'content-type: application/dns-message' \ 
--data-binary @- https://cloudflare-dns.com/dns-query -o - | xxd 
00000000: abcd 8180 0001 0002 0000 0001 0667 6974  .............git 
00000010: 6875 6203 636f 6d00 0001 0001 c00c 0001  hub.com......... 
00000020: 0001 0000 0013 0004 8c52 7604 c00c 0001  .........Rv..... 
00000030: 0001 0000 0013 0004 8c52 7603 0000 2905  .........Rv...). 
00000040: ac00 0000 0000 00                        ....... 

```
## Appendix B - reversing base-16 complement

```
If you are a bit acquainted with hex you dont need to convert to binary.
Just take the base-16 complement of each digit, and add 1 to the result.
So you get 0C5E. Add 1 and here's your result: 0C5F.
for a faster approach you can also flip the bits left to very first set bit
and find out the 2s complement.
(instead of finding 1ns and then adding 1 to it) 
1111 0011 1010 0001 toggle the bits left to first set bit
0000 1100 0101 1111
I expect you would like this if bit pattern is changed to binary than hex :)

The TTL entity/value was foundation in DNSP development, considered for sake of caching.
With the advent of DNS-over-HTTPS RFC standard, the need to serve (and properly expire)
caches became imperative. TTL specifies a maximum time to live, not a mandatory time to live.
RFC2181: "Maximum of 2^31 - 1.  When transmitted, this value shall be encoded in the less
significant 31 bits of the 32 bit TTL field, with the most significant, or sign, bit set
to zero. Implementations should treat TTL values received with the most significant bit set
as if the entire value received was zero. Implementations are always free to place an upper
bound on any TTL received, and treat any larger values as if they were that upper bound. 

0x08 - backspace \010 octal
0x09 - horizontal tab
0x0a - linefeed
0x0b - vertical tab \013 octal
0x0c - form feed
0x0d - carriage return
0x20 - space

```
## Appendix C . DNS FAILURE MESSAGES

```
DNS_MODE_ERROR should truncate message instead of building it up ... 
Server failure (0x8182), but what if we wanted an NXDOMAIN (0x....) ?
Being DNSP still under test, we do not care much. Nobody likes failures */

NOERROR (RCODE:0)        : DNS Query completed successfully
FORMERR (RCODE:1)        : DNS Query Format Error
SERVFAIL (RCODE:2)       : Server failed to complete the DNS request
NXDOMAIN (RCODE:3)       : Domain name does not exist
NOTIMP (RCODE:4)         : Function not implemented
REFUSED (RCODE:5)        : The server refused to answer for the query
YXDOMAIN (RCODE:6)       : Name that should not exist, does exist
XRRSET (RCODE:7)         : RRset that should not exist, does exist
NOTAUTH (RCODE:9)        : Server not authoritative for the zone
NOTZONE (RCODE:10)       : Name not in zone
11-15           available for assignment
16    BADVERS   Bad OPT Version             
16    BADSIG    TSIG Signature Failure      
17    BADKEY    Key not recognized          
18    BADTIME   Signature out of time window
19    BADMODE   Bad TKEY Mode               
20    BADNAME   Duplicate key name          
21    BADALG    Algorithm not supported     
22-3840         available for assignment
  0x0016-0x0F00
3841-4095       Private Use
  0x0F01-0x0FFF
4096-65535      available for assignment
  0x1000-0xFFFF

```

## Appendix D - Example HTTP Cache Headers

```
cache with HTTP/1.1 304 "Not Modified" 
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control 
 * REQUEST 
Cache-Control: max-age=<seconds> 
Cache-Control: max-stale[=<seconds>] 
Cache-Control: min-fresh=<seconds> 
Cache-Control: no-cache  
Cache-Control: no-store 
Cache-Control: no-transform 
Cache-Control: only-if-cached 
 *  RESPONSE 
Cache-Control: must-revalidate 
Cache-Control: no-cache 
Cache-Control: no-store 
Cache-Control: no-transform 
Cache-Control: public 
Cache-Control: private 
Cache-Control: proxy-revalidate 
Cache-Control: max-age=<seconds> 
Cache-Control: s-maxage=<seconds> 
 * NON-STANDARD 
Cache-Control: immutable  
Cache-Control: stale-while-revalidate=<seconds> 
Cache-Control: stale-if-error=<seconds> 

```
