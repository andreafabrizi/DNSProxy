#!/bin/bash

echo -n 'q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB'  | base64 -d | xxd
#00000000: abcd 0100 0001 0000 0000 0000 0377 7777  .............www
#00000010: 0765 7861 6d70 6c65 0363 6f6d 0000 0100  .example.com....
#00000020: 01

for i in $(seq 1 3); do
	for k in www.google.it www.facebook.fr www.repubblica.it www.wired.com www.amazon.fr www.cachot.ch www.facebook.it; do
		#echo -n "$k:" &&
		dig +short +timeout=10 +tries=1 -t A $k @127.0.0.1 2>/dev/null | head -1 &
		sleep 5
		dig +short +timeout=10 +tries=1 +tcp -t A $k @127.0.0.1 2>/dev/null | head -1 &
		sleep 5
		//dig +short +timeout=3 +tries=1 +tcp -t A $k @127.0.0.1 2>/dev/null | head -1
		# | egrep -v '(^;|^$)' &
	done
done
