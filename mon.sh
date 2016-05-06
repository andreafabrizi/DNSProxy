#!/bin/bash

#set -x

DNS=$1
PORT=$2
NUM=$3

if [ -z $1 ] || [ -z $2 ] || [ -z $3 ]; then
	echo "parameters missing... ./$(basename $0) 127.0.0.1 53 1000"
	echo "parameters missing... ./$(basename $0) server port queries"
	exit 127
fi

#cat DNS.txt | head -$NUM | \
#xargs -n 10 -I {} -P $(echo $NUM/10| bc) \
a=0
WAIT=""

for i in $(cat DNS.txt | head -$NUM); do
	if [ $a -lt $(echo $NUM/10| bc) ]; then
		dig +retry=0 -p $PORT $i @$DNS &
		WAIT="$WAIT $!"
		let a=a+1
	else
		dig +retry=0 -p $PORT $i @$DNS
		let a=0
		wait $WAIT 
	fi
done | grep -v 'timed out' | awk -v xxx=$NUM -F ' ' 'BEGIN{sum=0}{ if (/Query time/) sum+=$4 } END { print "\nAverage query time: "sum/xxx" ms ("sum","xxx")" }'
#|grep time
#dig {} @$DNS | grep -E '^[A-Za-z0-9]|Query time' | \
