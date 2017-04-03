# DNS Proxy

DNS proxy listens for incoming DNS requests (A,NS,MX,TXT,SRV..) on the local
interface (UDP only) and resolves correct addresses by using an external PHP
script, using standard HTTP(S) requests.

If you can't access VPN or tunnels  to resolve names externally (TOR users),
DNSProxy is a simple and efficient solution.

All you need to start resolving anonymous DNS is a PHP server hosting the
nslookup.php script (i.e. fantuz.net). This software is completeley 
TOR-friendly and requires minimal resources.

## Building

Building is easy on Mac and Ubuntu, CentOS, Fedora. Based on curl libs.

For debian/ubuntu users:  
`apt-get install libcurl4-openssl-dev`
then compile with
`make`
or
 gcc dnsp.c -W -lcurl -g -lpthread -DTLS -rdynamic -lrt -o dnsp

## Usage 

```bash
sudo ./dnsp -p 53 -l 127.0.0.1 -h 127.0.0.1 -r 8118 -w 80 -s https://www.fantuz.net/nslookup.php
sudo ./dnsp -p 53 -l 127.0.0.1 -w 443 -s https://www.fantuz.net/nslookup.php
```
In this example, DNS proxy listens on local UDP port 53 and sends the 
request to the PHP script hosted at the example address, eventually through
proxy (i.e. TOR, squid, charles).

You can rely on any HTTP/HTTPS proxy server, should you need caching. Any
polipo, squid, nginx, charles, SOCKS, TOR, will work properly with DNSP.

You can also run DNSP on plain HTTP without proxy, but mind that your
navigation won't be anonymous.... so better use HTTPS at least :)

**IMPORTANT:** Please, don't use the script hosted on my server as demonstration.
It might be subjected to umpredicted change, offlining, defacing.
Instead - host yourself the nslookup.php script, and spread it on a friend's server!
The more we are, the less DNS becomes a 'trackable' TOR leak.

```bash
 dnsp 1.01
 usage: dnsp -l [local_host] -h [proxy_host] -r [proxy_port] -w [webport] \
	-s [lookup_script] -t [stack_size]

 OPTIONS:
      -l		 Local server address
      -p		 Local server port
      -h		 Remote proxy address
      -r		 Remote proxy port
      -u		 Proxy username (optional)
      -k		 Proxy password (optional)
      -s		 Lookup script URL
      -w		 Webserver port (optional, default 80)
      -t		 Stack size in format 0x1000000 (MB)
      -v		 Enable juicy DEBUG logging

 Example: dnsp -p 53 -l 127.0.0.1 -h 127.0.0.1 -r 8118 -w 80 \
	-s https://www.fantuz.net/nslookup.php -t 0x1000000

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
 few milliseconds, after the first recursive resolution.
 
Still bugs presents, i.e.:
 - dig +short -p 5353 -x 104.27.133.199 @localhost
 - ;; Warning: Message parser reports malformed message packet.


## Changelog:
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
