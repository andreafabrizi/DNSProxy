#!/bin/bash

for i in $(seq 1 3); do
	for k in www.google.it www.facebook.fr www.repubblica.it www.wired.com www.amazon.fr www.cachot.ch www.facebook.it; do
		#echo -n "$k:" &&
		dig +short +timeout=10 +tries=1 -t A $k @127.0.0.1 2>/dev/null | head -1 &
		# | egrep -v '(^;|^$)' &
	done
done
