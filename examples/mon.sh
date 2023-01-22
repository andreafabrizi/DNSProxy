#!/bin/bash

DNS=$1
PORT=$2
NUM=$3
FILE='./DNS_example_input.txt'

if [ -z $1 ] || [ -z $2 ] || [ -z $3 ]; then
	echo "parameters missing... ./$(basename $0) 127.0.0.1 53 1000"
	echo "parameters missing... ./$(basename $0) server port queries"
	exit 127
fi

#cat DNS.txt | head -$NUM | \
#xargs -n 10 -I {} -P $(echo $NUM/10| bc) \
a=1
b=0
WAIT=""

# | xargs -n 5 -I {} -P $(echo $NUM/5| bc)
for i in $(shuf -n $NUM $FILE); do
	#if [ $a -lt $(echo $NUM/10 | bc) ]; then
	if [ $a -gt $(($NUM % 10)) ]; then
		dig +retry=0 -p $PORT $i @$DNS &
		WAIT="$WAIT $!"
		let a=a+1
	else
		dig +retry=0 -p $PORT $i @$DNS
		let a=0
		wait $WAIT 
	fi
done | tee mon.count | grep -v 'timed out' | awk -v xxx=$NUM -v tot=0 -F ' ' 'BEGIN{sum=0}{ if (/Query time/) {sum+=$4 ; tot+=1;} } END { print "\nAverage query time: "sum/xxx" ms ("tot"/"xxx")" }'
#|grep time
#dig {} @$DNS | grep -E '^[A-Za-z0-9]|Query time' | \
echo "Failed requests: "$(grep -c 'timed out' mon.count)/$NUM
