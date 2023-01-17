# DNSProxy - RFC-compliant DNS-over-HTTPS proxy

## Why DNSProxy ?
### DNS transport tests, gone too far :)

Historically, DNSProxy was developed for very exotic reasons: simplify DNS
messaging between base-station and "client" airplanes over satellite link, and 
protect myself while surfing TOR by avoiding DNS/UDP leaks.

First _niche_ use-case: DNS UDP messages were lost within the satellite pipe
but migrating that class of traffic on standard DNS/TCP was not an option as the
platform was not able to receive such datagrams, hence I came up inventing this
hybrid "transport and caching protocol" to carry the precious information.

The second source of inspiration came from the observation of another common
and well-known issue: TOR privacy leaks. One candidate protocol to try out was
SOCKS, and multiple mini-proxy projects existed. After some successful testing
socksifying DNS/TCP, it turned out that DNS/UDP cannot be SOCKS-encapsulated.
The only choice left was to vehiculate DNS message _inside_ another standard
protocol that could be -indeed- easily ecapsulated on TOR networks.

The protocol of choice was then "HTTP" in it's secure implementation "HTTPS".

### Standardization of protocol
I started focusing on different use-cases and came up with the definition of the
pseudo-protocol around 2009 or 2010. Back then, I could not imagine that this
humble invention would one day result in me collaborating with IETF (Internet
Engineering Task Force) board in the developement and publication of standard
state-of-the-art DNS-over-HTTPS, RFC-8484 (https://tools.ietf.org/html/rfc8484).

A new MIME type has since been defined (application/dns-message) and protocol
design goals are perfectly clear. For more information about MIME types refer to
IANA's website https://www.iana.org/assignments/media-types/media-types.xhtml.

All the coding efforts -collected in this repository- aim to support the deploy
of **DoH client/server** as a rudimental and non-intrusive system-resolver. 

Since publication of RFC-8484 DNSProxy software has been split in two branches:
- **dnsp-h2 supports only RFC-8484-compliant format**.
- **dnsp** - now legacy - used to support non-compliant pre-DoH formats.

DNSProxy software did support different flavours of DoH formats, being:
 - **application/dns-message [RFC-8484]**: RFC8484-compliant, purest DoH format
 - **application/dns+json    [RFC-8427]**: JSON format, legacy - DO NOT USE
 - **application/dns         [RFC-4027]**: text/data format - DO NOT USE

Further developement of support for newer QUIC/HTTP/3 is now work-in-progress.

### How does it work ?
To run dnsp-h2 server you do not need ANY access to UDP proto nor to port 53.
All requests/responses will be transported within TCP HTTP/2.

Once started, dnsp-h2 will listen for incoming DNS requests (A,NS,MX,TXT,SRV)
on both UDP & TCP sockets with multiple threads. As a query arrives, DNSProxy
will parse its contents, transforming DNS in b64-encoded HTTP request and
forward that raw content towards a DoH service provider.

The DoH provider in turn will deal with underlying DNS resolution and return
HTTP response. DNSProxy will receive incoming HTTP data and will opportunely
craft a DNS response to the calling UDP/TCP DNS client.

Exchange of messaging relies on means of standardized HTTP request and response
supported by different helpers as:
 - HTTP header parser (for TTL, CF-RAY caching)
 - a TCP restamping helper
 - a module for blacklisting
 - b64 logic, checksumming, ...

DNSProxy leverage the fancyness of HTTP, DNS, TLS, hence debug and monitor are
simplified and easy with standard toolset. Hooks and symbols are in place,
logging is quite self-explanatory and clean. Documentation is kept up-to-date
for the benefit of community, and every new features logged in changelog.

## Architecture
### Design Overview

A classic DNS messaging schema except that raw packets are carried over HTTP/2
guaranteeing against _privacy leaks_ (see PRIVACY disclaimer below).

DNSProxy is a rapid and efficient solution if you can't access "secured" tunnels
to resolve domain names externally (TOR users, Chinese Wall of Fire, evil VPN).

Robustness of architecture proves DNSProxy a very scalable and smart solution.
```
             +---------------------------+
  +----------| DNSProxy re-uses original | <<----------+
  |          |  sockets [ DNS & HTTPS ]  |             |     DNSProxy parses
  |          +---------------------------+             |    HTTP raw response,
  |                         ^                          |   builds DNS reply and
  |                         ^                          |  sends back via TCP/UDP
  |                         |   IF answer found        |     as per RFC-1035
  |                         | on HTTP or disk cache    |
  |                         |  THEN faster reply       |   libCURL handles HTTP
  v                         |    same security         |  requests and responses
  v                         :                          :
 +---------------+       +--------+---------+       /------------------\
 |   client OS   | --->> +  DNSProxy parser + --->> |   DoH resolver   |
 +---------------+       +--------+---------+       +------------------+
 | sends request |       |  blacklist, TTL  |       |Google, CF, custom|
 | to DNS server |       | pooling, caching |       | (RFC-8484-aware) |
 +---------------+       +------------------+       \------------------/
    :                                                     ^
    |                                                     ^
    | DNS queries to DNSP daemon on 127.0.0.1:53 will be  |
    |   tunneled towards a DoH-aware resolver webservice  |
    +-----------------------------------------------------+
```
We generally refer to *DNSProxy* software by considering both DoH and pre-DoH
branches, as design foundations are the same for both. Consider dnsp-h2 as the
"RFC-compliant spinoff" of old/abandoned dnsp:
- *dnsp-h2* will take care of crafting well-formed DNS packets in accordance to
  foundation RFCs RFC-1035 and RFC-8484.
- *dnsp* is now **deprecated** and should not be used. It historically supported
  RFC-1035 DNS responses, but had slightly different architecture and was born
  long before the DoH draft (therefore, it only support pre-DoH formats).

Also note that *dnsp* binary (pre-DOH version of DNSProxy) is only kept in
repository for historical reasons, offers  no backward-compatibility and may
soon disappear. Please only use, refer to and commit towards *dnsp-h2* branch.

Commits for other legacy components will not be accepted.

### Basic ideas and more advanced features
- DNS-over-HTTPS proxy compliant with RFC-8484 and other older non-standards
- HTTP/2 is the minimum requirement for DoH and **dnsp-h2** only supports >= h2
- for non-standard non-DoH experiments, you may look at **dnsp**, now DEPRECATED
- **dnsp-h2** provides ability to set specific headers according to cache
  requirements, translating HTTP cache Validity into DNS TTL value
- **dnsp-h2** offers an option to dump response packets, eventually to serve
  those contents via another HTTP(S) DoH-compliant webserver (if you plan to
  offer a DoH resolver for example).
- both **dnps-h2** and **dnsp** offer a feature based on FOLLOWLOCATION which in
  turn will spawn dedicated threads and enable browser cache preemption for the
  benefit of user experience.

To KISS, in order to start resolving anonymous DNS over HTTP(S) all you need is:
- the C software, available as source or compiled **(dnsp-h2 and dnsp)**
- a PHP-server hosting *nslookup-doh.php* resolver script **(needed only by
legacy dnsp)**

This software is OSS, TOR-friendly and requires minimal resources. Enjoy !

### Caching answers (on disk, on another proxy, in the network)
DNSProxy is capable of leveraging cache on very different locations:
- a first layer of DNS cache is populated on disk as a result of raw answer 
  dump, obtained from the remote webservice. Note: this binary content can be
  reused both from a DNS and a secondary HTTP DoH server. Call it "raw packet".
- a second layer of DoH cache can be demanded to an HTTPS-capable proxy (i.e.
  _charles proxy_). Can be referred as "volountary cache" adhering to standards.
- a third layer of DNS cache is considered to be managed by DoH resolver's for
  example via implementation of CDN, Anycast, ISP caching. This this one can be
  referred to as "cache in the network".

NB: Some parts of this "network-distributed cache" might be held on CDN for
transient period. An intermediate cache layer is often present nowadays unless
forbidden via headers or TTL manipulation.

Tested on CloudFlare, Google Cloud Platform, NGINX, Apache, SQUID, polipo, REDIS

### Proxifying your proxy, for debug, access or caching reasons
**DNSProxy may be configured to pass-through additional chain of proxies**
(i.e. TOR, enterprise-proxy, locked-down countries, you name it). Important to
note, "a cache" is often availaible "in the network" (i.e. on CDN) therefore
there is no impellent mandatory need for a local cache (eventually, speed).

To complexify the picture, HTTP/2 (TLS) makes cache rather uneasy to share.

Should you be willing to perform forensics or "response caching and sharing"
you can still rely on standard HTTPS proxy MITM techniques; *any HTTP(S) proxy*
will work properly with DNSProxy as polipo, squid, nginx, charles, burp, ...

**Though, the majority of DNSProxy users will directly run dnsp-h2 without any 
chained proxy settings**. The DNSProxy server will therefore connect directly to
the remote webservice (resolver) not leveraging any specific cache.

**IMPORTANT:** DoH resolvers around the world increase global DNS privacy !

## Running DNSProxy
### Pre-requisites check
Build is easy on Linux, Mac, UNIX and even Windows; DNSProxy is based on fairly
simple dependencies on libcurl CURL C library, pthread, SSL/TLS, all standards.
A recent version of nghttp2 is needed to leverage HTTP/2 CURL capabilities.

To fullfill requirements on a Linux OS, run the following package installations:
```bash
sudo apt-get install libcurl4-openssl-dev curl libsslcommon2-dev libssl-dev \
ca-certs brotli gnutls-bin openssl libtlsh-dev
```
```bash
git clone https://github.com/clibs/clib.git /tmp/clib
cd /tmp/clib
make
sudo make install
sudo clib install jwerle/b64.c
sudo clib install jwerle/libok
```
### Building and Installing.
Once pre-requisites checked, you will be able to *compile software* by running:
```bash
cd -
make
```
### Deploy DoH standard infrastructure
Start a fully-compliant DoH/h2 server. _Only applies to **standard dnsp-h2** binary_.

#### STEP 0. HTTPS webservices are hard-coded into dnsp-h2 server
See APPENDIX E for extensive list.
#### STEP 0. Optionally configure an HTTPS MITM proxy - for debug or caching reasons
Install and configure SSL MITM intercepting proxy as charles or burp
#### STEP 1. Invoke *dnsp-h2* and start answering DNS queries
```bash
# Run DNSProxy with standard Google & Cloudflare DoH resolvers. Surf anonymously in the simplest direct mode
dnsp-h2 -Q

# Run DNSProxy behind HTTPS caching proxy (i.e. charles, burp) for debug or caching reasons
dnsp-h2 -Q -H http://192.168.3.93/ -r 8118
dnsp-h2 -Q -H http://aremoteproxyservice.internal/ -r 3128
```
### Deploy pre-DoH non-standard infrastructure - DEPRECATED
Start a pre-h2 pre-DoH (HTTP/1.1) legacy server. _Only applies to **dnsp legacy binary**_.

#### STEP 1. Deploy the PHP nameserver webservice - DEPRECATED
Deploy **nslookup-doh.php** on a webserver, possibly not your local machine (see
DISCLAIMER). If you ignore how-to carry on such deploy task or you do not have
access to any of such services, just use the generic webservice as in examples.

#### STEP 2. Configure optional HTTP proxy access - DEPRECATED
Setup an HTTP caching proxy on the local machine or eventually on a remote host.
Provide host and port of your proxy server as *dnsp* program arguments.

#### STEP 3. Invoke *dnsp* and start answering DNS queries - EPRECATED
Meant to answer DNS queries but using non standard-resolver.
```bash
# Run non-compliant pre-DoH DNSProxy without chained proxy:
dnsp -l 127.0.0.1 -s https://www.fantuz.net/nslookup-doh.php

# Run non-compliant non-DoH HTTP proxy (i.e. squid, polipo) with chained proxy
dnsp -H http://192.168.3.93/ -r 8118 -s https://abc.com/nslookup.php
```
### Getting help on every advanced, experimental and deprecated option
```bash
user@machine:~/DNSProxy$ ./dnsp-h2 -h

 dnsp-h2 v3.3.0, copyright 2010-2023 Massimiliano Fantuzzi HB9GUS, MIT License

 usage: dnsp-h2 [-l <local_host_address>] [-p <local_port>] [-H <proxy_host>]
	[-r <proxy_port>] [-u <user>] [-k <pass>] [-d <path>] [-Q] 
	[ -s <DNS_lookup_resolving_service_URL> ] [-w <lookup_port>]

 OPTIONS:
  [ -Q           ]	 Extract TTL from DoH provider HTTP response (suggested)
  [ -l <IP/FQDN> ]	 Local server address, default to all active interfaces
  [ -p <53>      ]	 Local server port, default to 53
  [ -H <IP/FQDN> ]	 MITM/Cache Proxy Address (HTTPS-capable as charles)
  [ -r <3128>    ]	 MITM/Cache Proxy Port
  [ -u <user>    ]	 MITM/Cache Proxy Username
  [ -k <pass>    ]	 MITM/Cache Proxy Password
  [ -d <path>    ]	 Output directory for storage of responses

 ADVANCED OPTIONS:
  [ -T <n>       ]	 Override TTL [0-2147483647] defined in RFC-2181
  [ -Z <n>       ]	 Override TCP response size to be any 2 bytes at choice

  [ -v           ]	 Enable debug
  [ -n           ]	 Enable raw DNS dump
  [ -C           ]	 Enable CURL debug
  [ -N           ]	 Enable COUNTERS debug
  [ -R           ]	 Enable THREADS debug
  [ -L           ]	 Enable LOCKS debug
  [ -X           ]	 Enable EXTRA debug

 EXPERT OPTIONS:
  [ -s <URL>     ]	 Webservice Lookup Script URL (deprecated, old dnsp)
  [ -w <443>     ]	 Webservice Lookup Port (deprecated, old dnsp)
  [ -r           ]	 Enable CURL resolve and avoid extra gethostbyname
  [ -t <n>       ]	 Stack size in format 0x1000000 (MB)


 For a more inclusive list of DoH providers, clients, servers and design, see:
 - https://tools.ietf.org/html/rfc8484
 - https://github.com/curl/curl/wiki/DNS-over-HTTPS
 - https://it.wikipedia.org/wiki/DNS_over_HTTPS#cite_note-8
```
## Integration
DNSPproxy has been built with _simplicity_ and _standards_ in mind. On a modern
Linux box- an extra layer of caching DNS is often provided by nscd or dnsmasq
services. Even in presence of such caches all the UDP+TCP DNS traffic accounts
for a sensible and constant bandwidth consumption.

In the current internet scenario, dominated by CDN, cloud, anycasting and
load-balancing, the opportunity of having "HTTP insecure cache" is becoming less
and less attractive due to hardened security layers and increasing computing
speed of peers. Still, a "secure DNS and HTTPS cache" may be very desirable,
leading to the availability of disk-cache (recently added feature).

As the whole internet has been - a **standardised work in progress** in the past
40 years - so is *DNSProxy*: experimental software, opensource, community tool.

_DNSProxy is not an alternative to other caching services_. **DoH webservices**
do allow the creation of a new layer of distributed cache, secured by means of
standardised HTTP protocol.

DNSProxy represents an _alternative transport method of old-style DNS_. As I
often stated, DNSProxy was conceived as a way to help overcome censorship and
trackability via DNS. As you might question -YES- **DNS-over-HTTPS** may leave
traces, maybe not anymore on UDP level but eventually on intermediate HTTP(S)
webservers' logs, for example on am untrusted DoH server.

I never meant to state that DNSProxy is faster or better than other DNS servers
but it is definitely original on its own. A buggy piece of threaded code which
I created to help people _transporting_ and _sharing_ DNS data in a fancy way.

### Issues when launching an instance of dnsp or dnsp-h2
You may have to stop other running daemons bound to 127.0.0.1:53, as:
_dsndist,bind,resolvconf,systemd-resolvconf_ and other DNS servers or proxies

### Testing deployment of DNSProxy using dig or nslookup
Now open a terminal and invoke **dig** (or _nslookup_) to test resolver
capabilities over UDP or TCP. The test consist in resolving an hostname against
the server instance of DNSProxy,

To test the UDP server, type the following and expect consistent output:
```bash
 $ dig news.google.com @127.0.0.1
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
 $ dig +tcp facebook.com @127.0.0.1
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9475
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; QUESTION SECTION:
;facebook.com.          IN  A
;; ANSWER SECTION:
facebook.com.       524549  IN  A   185.60.216.35
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; MSG SIZE  rcvd: 46
```
Once listeners have been verified to work, you may safely replace instances of
"/etc/resolv.conf" to direct requests against DNSProxy daemon by inserting the
following line and remove other _"nameserver"_ entries already present:
```
nameserver 127.0.0.1
```
NB: in case your OS resolution is configured via systemd-resolved, you would
need to edit the proper systemd service file at /etc/systemd/resolved.conf.

### Debug deployment of dnsp-h2 using tcpdump and a MITM proxy
At this point, you may already:
- have started your traffic capture, either using wireshark, tshark or tcpdump.
- have a working MITM proxy setup i.e. charles, burp or similar software.

![alt text](https://raw.githubusercontent.com/fantuz/DNSProxy/master/capture-http2.png)

The capture shows an HTTP/2 dialog as seen by wireshark: this is the only way
to show a valid MITM HTTP/2 capture without having to load key material intended
for dissection.

This old example dialog shows that a correct negotiation does not happen, along
with an insecure URI, a pre-DoH prototype http://www.fantuz.net/nslookup-doh.php
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

Example capture showing correspondance between sent and received messages, and
a valid logic structure of raw packet.
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
```
### Deployment of nslookup-doh.php and nslookup.php PHP scripts - DEPRECATED

To test the deployment of nslookup-doh.php along with correct DNS resolution,
you could use **curl** utility within a shell. Replace URL value in accordance
with your favourite script location.

Here are two simple one-liners I use to check my deploys:
```bash
 $ curl -s -H "Host: www.fantuz.net" -H "Remote Address:104.27.133.199:80" -H "User-Agent:Mozilla/5.0 \
(Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 \
Safari/537.36" 'http://www.fantuz.net/nslookup-doh.php?host=fantuz.net&type=NS' | xxd

 $ curl -s -H "Host: php-dns.appspot.com" -H "User-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36" \
'http://php-dns.appspot.com/helloworld.php?host=fantuz.net&type=NS' | xxd
```
Request should end with bits _0D0A_ (HEX is easy to read with xxd):
```
00000000: 7364 6e73 332e 7668 6f73 7469 6e67 2d69  sdns3.vhosting-i
00000010: 742e 636f 6d0d 0a                        t.com..
```
## Versioning and evolution of DNSProxy family
### Changelog:
#### Version 3.3.0 - January 2023:
* adjusted to POST by default (no more GET with visible _dns=_ string)
* reduced memory footprint
* better debug, Makefile, debug symbols for GDB
* caching of responses on disk
* multiple requests are issues in parallel against different DoH providers
* supporting multiple levels of subdomains, CNAME, mixed object responses
* updated dependecies of OK and B64 libraries
#### Version 3.0 - August 2020:
* fixed TCP listener !
* implement correct calculation of encapsulation overhead for TCP DNS messages
#### Version 2.5 - February 2019:
* perfect parsing of HTTP reply (for TTL-rewriting purposes)
* testing different scenarios with GET and POST towards DoH resolvers (unstable)
* testing further TCP and UDP sturdyness
#### Version 2.5 - February 2019:
* provide base64urlencode of DNS requests !
* implemented dump of "cache-control" headers from PHP/DoH resolver into DNS packet
* added new _build\_dns_ to comply with DoH/RFC format, instead of pre-DoH _build\_dns\_response_
* implement TRANSACTION-ID override (0xABCD by default)
* implement TYPE override (0x00 by default)
* make sure we set headers _accept_ and _content-type_ to _"application/dns"_ for both POST and GET scenarios
#### Version 2.2 - January 2019:
* designed and implemented both TCP and UDP listeners
#### Version 2 - March 2018:
* Added TCP query/response support !
* backend RFC-compliancy: base64urlencode DNS query (DNSProxy HTTP client)
* frontend RFC-compliancy: raw DNS printout (PHP script, webservice resolver)
* preemptive HTTP cache population as option. Using ad-hoc Location header, we
  can force DNSProxy server to issue a parallel GET towards requested website 
  in order to preemptively populate local and intermediate caches. (Not many
  use-cases except in a few scenarios i.e. surfing through high-delay network.
* added the arduino+ethernet library with new select() function
* legacy **dnsp** version freeze, development will proceed only for **dnsp-h2**
  (since Hackathon 101 London 3/2018).
#### Version 1.6 - March 2018:
* fixed implementation of intermediate proxy
* commented references to different modes (threaded/forked, mutex, semaphores)
* updated examples for SQUID in place of POLIPO (unfortunately EOL)
* almost REDIS-ready _via https://github.com/redis/hiredis_
* other thought and implementations pending
#### Version 1.5 - February 2018:
* added references and mentions to IETF DoH (HTTP/2, single connection multiple
  streams, opportunistic PUSH)
* fixed README and easen installation/testing procedure
* fixed NS/CNAME answers (C) and resolver script (PHP code)
* added Arduino double ethernet shield script
* added the GO version made by chinese contributors inspired at my software
* MIT License in accordance to transfer of rights operated via mail by Andrea
* lazy caching, CURL following redirects
* deleted some junk files, renamed dirs for clarity
* multiversion PHP 5/7, depending on hosting provider due to slightly different
  implementation of print(), random css, incompatibility of h1/h2, headers, etc
#### Version 1.01 - March 2017:
* works with millions query [not anymore since I added TCP]
* few issues caching of CloudFlare-alike caches (304 no-more ?) or Etag header
* going back to either threads or vfork...
* more crash-test, memory-leak hunting, strace statistics and performance tests
* published an improved Varnish configuration
#### Version 1.01 - April 2015:
* HTTPS support over legacy non-DoH HTTP (even more privacy)
* Pseudo-Multithreading listener/responder
* Better nginx/polipo setup but not anymore useful when switching to HTTP/2
* Stack size option being deprecated, no valid use-case to keep such
* Drafting addition of TCP listener logic
* Some issue to set the proper ETag on polipo
#### Version 0.99 - July 2014:
* Add HTTP port selection (80/443)
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
### Features being actively developed:
* (in progress) support far more than A, AAAA, CNAME and NS. My pre-DoH test protocol supported MX, PTR and ALL types
* (in progress) offer choice on method. So far only POST is supported as better privacy
* (in progress) parallelize requests
* (todo) find out why some requests encounter ";; Question section mismatch: got fantuz.net/RESERVED0/IN"
* (todo) add a /stats backend
* (done) save HEX packet structure and serve it as HTTP content from DNSP daemon priming the local cache
* (done) reduce memory impact (strace, gdb, valgrind)
* (done) restore performances, currently impacted by TCP handler
### Lower priority ideas:
* (todo) choose the faster response or wait and compare all parallel responses
* (todo) worth looking at QUIC, the UDP-multiplexing upcoming HTTP/3 standard.
* (todo) implement HTTP/2 PUSH, for smoother and opportunistic DNS answers. Remember: there's no ID field in DoH.
* (todo) use h2 "Warning" headers to signal events or failures
* (todo) perform DNSSEC validation tests
* (todo) add a "--resolve" option to pin DoH request to an IP address (see SNI debate on IETF mailing lists)
* (todo) add an option to provide dynamic list of blacklisted domains (to be read in from file or STDIN)
* (todo) add switch to leverage REUSEPORT and/or REUSEADDRESS
* (pending decision) to use directly NGHTTP2 in place of CURL. FYI CURL relies on NGHTTP2
* (pending decision) REDIS: implement or drop
* test build on Debian, Windows, MacOS (only tested with Ubuntu 14-18 and very old MacOS)
* test bynary distribution on Debian, Windows, MacOS
### References:
* https://tools.ietf.org/html/rfc8484
* https://datatracker.ietf.org/meeting/101/materials/slides-101-hackathon-sessa-dnsproxy-local-dns-over-http-private-resolver
* https://www.reddit.com/user/fantamix/comments/7yotib/dnsp\_a\_dns\_proxy\_to\_avoid\_dns\_leakage/
* https://www.reddit.com/r/hacking/comments/7zjbv2/why\_to\_use\_a\_dns\_proxy\_why\_shall\_it\_be/
* https://github.com/curl/doh/blob/master/doh.c
* https://www.meetup.com/it-IT/Geneva-Legal-Hackers/messages/boards/thread/51438161
* https://tools.ietf.org/html/draft-ietf-dnsop-dns-wireformat-http-01
* https://igit.github.io/

## Further information and bibliography
### Appendix A - Common Proxy Headers
```
Common proxy ports: 
  1080 (generic HTTP proxy) 
  3128 (squid) 
  8118 (polipo) 
  8888 (simplehttp2server) 
  9500 (tor) 
  1090 (socks) 

 $ echo | openssl s_client -showcerts -servername php-dns.appspot.com -connect php-dns.appspot.com:443 2>/dev/null | openssl x509 -inform pem -noout -text

 $ curl --http2 -I 'https://www.fantuz.net/nslookup.php?name=google.it'
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

 # POST 
 $ echo -n 'q80BIAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | base64 -d 2>/dev/null | curl -H 'content-type: application/dns-message' --data-binary @- https://cloudflare-dns.com/dns-query -o - | hexdump 
 
 # GET 
 $ curl -H 'accept: application/dns-message' -v 'https://cloudflare-dns.com/dns-query?dns=q80BIAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | hexdump 
 
 $ curl -o - 'https://cloudflare-dns.com/dns-query?dns=q80BIAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB' -H 'authority: cloudflare-dns.com' \ 
-H 'upgrade-insecure-requests: 1' \ 
-H 'user-agent: curl 7.64.1-DEV (x86_64-pc-linux-gnu) libcurl/7.64.1-DEV OpenSSL/1.0.2g zlib/1.2.11 nghttp2/1.37.0-DEV' \ 
-H 'accept: application/dns-message' -H 'accept-encoding: gzip, deflate, br' -H 'accept-language: en-US,en;q=0.9' --compressed | xxd 
 
 $ echo -n 'q80BAAABAAAAAAAABmdpdGh1YgNjb20AAAEAAQ' | base64 -d 2>/dev/null | curl -s -H 'content-type: application/dns-message' \ 
--data-binary @- https://cloudflare-dns.com/dns-query -o - | xxd 
00000000: abcd 8180 0001 0002 0000 0001 0667 6974  .............git 
00000010: 6875 6203 636f 6d00 0001 0001 c00c 0001  hub.com......... 
00000020: 0001 0000 0013 0004 8c52 7604 c00c 0001  .........Rv..... 
00000030: 0001 0000 0013 0004 8c52 7603 0000 2905  .........Rv...). 
00000040: ac00 0000 0000 00                        ....... 
```
### Appendix B - reversing base-16 complement - inspiration for coding
```
If you are a bit acquainted with hex you dont need to convert to binary. Just
take the base-16 complement of each digit, and add 1 to the result. So you get
0C5E. Add 1 and here's your result: 0C5F.

For a faster approach you can also flip the bits left to very first set bit and
find out the 2s complement, instead of finding 1ns and then adding 1 to it.
1111 0011 1010 0001 toggle the bits left to first set bit
0000 1100 0101 1111

I expect you would like this if bit pattern is changed to binary then hex :)
```
### Appendix C - DNS FAILURE MESSAGES
Nobody likes failures.
DNS\_MODE\_ERROR should truncate message instead of building up response.
Using "Server failure (0x8182)" but what if we wanted an NXDOMAIN (0x....) ?
```
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
### Appendix D - Thoughts on TTL and recap on HTTP Cache Headers
Concept of TTL has been taken in account since the foundation of DNSProxy
developments for sake of caching purposes. With the advent of DNS-over-HTTPS RFC
as a standard the need to serve and properly expire caches became imperative.

TTL specifies a maximum time to live, not a mandatory time to live. RFC-2181
defines a _maximum of 2^31 - 1_. When transmitted, this value shall be encoded
in the less significant 31 bits of the 32 bit TTL field, with the most
significant, or sign, bit set to zero. Implementations should treat TTL values
received with the most significant bit set as if the entire value received was
zero. Implementations are always free to place an upper bound on any TTL 
received, and treat any larger values as if they were that upper bound. 
```
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control 
cache with HTTP/1.1 304 "Not Modified" 
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
### Appendix E - Non-inclusive DoH providers list
* 1.1.1.1
* 8.8.8.8
* see list on https://github.com/curl/curl/wiki/DNS-over-HTTPS#publicly-available-servers

## License
MIT license, all rights included.

## Disclaimer
__IF ANONIMITY IS A CONCERN__
DNSProxy is lazily tunneling DNS into HTTPS using curllib and nghttp2. Such
encapsulation **do avoid leakage** of DNS queries. Using DNS-over-HTTPS results
in impossibility to eavesdrop or spoof DNS traffic between client and final DoH
provider, given the additional security layer provided by HTTP/2.

__IF SPEED IS A CONCERN__
Performances of underlying sys-calls do lie outside the scope of DNSProxy scope.
Long testing has been carried on, sufficiently to say the software has no flaw,
no leakage, only a lot of verbosity, unnecessarly parallel logic, legacy support
for pre-standard DoH and other less-efficient routines.

**Do not forget to set 127.0.0.1 as your unique system resolver** via
common system configuration files (as /etc/resolv.conf or systemd-resolved).

