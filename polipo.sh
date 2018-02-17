#!/bin/bash

##diskCacheRoot = "/tmp/polipo/"
#diskCacheRoot = "/var/cache/polipo/"
##localDocumentRoot = "/usr/share/polipo/www/doc/"

mkdir /tmp/polipo

if [ -d /var/cache/polipo/ ]; then
	polipo -c polipo.conf &
	tail -f /var/cache/polipo-access.log
fi

