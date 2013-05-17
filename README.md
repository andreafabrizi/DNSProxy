# DNS Proxy

DNS proxy listens for incoming DNS requests on the local interface and 
resolves remote hosts using an external PHP script, through http proxy requests. 

If you can't use VPN, UDP tunnels or other methods to resolve external names 
in your LAN, DNS proxy is a good and simple solution.

## Building

For debian/ubuntu users:  
`apt-get install libcurl4-openssl-dev`

then

`make`

## Usage 

```bash
dnsp -l 127.0.0.1 -h 10.0.0.2 -r 8080 -s http://www.andreafabrizi.it/nslookup.php
```
In this case, DNS proxy listens on port 53 (bind on 127.0.0.1) and sends the
requests to external script through the 10.0.0.2:8080 proxy.

**IMPORTANT:** Please, don't use the script hosted on my server, it's only for testing purpose. 
Instead host the nslookup.php script on your own server or use a free hosting services. Thanks!

```bash
 dnsp 0.5
 usage: dnsp -l [local_host] -h [proxy_host] -r [proxy_port] -s [lookup_script]

 OPTIONS:
      -v  	 Enable DEBUG mode
      -p		 Local port
      -l		 Local host
      -r		 Proxy port
      -h		 Proxy host
      -u		 Proxy username (optional)
      -k		 Proxy password (optional)
      -s		 Lookup script URL
```

## Changelog:

Version 0.5 - May 17 2013
* Add proxy authentication support
* port option is now optional (default is 53)
* Minor bug fixes

Version 0.4 - November 16 2009
* Now using libCurl for http requests
* Implemented concurrent DNS server
* Bug fixes
* Code clean

Version 0.1 - April 09 2009
* Initial release
