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
		dig +retry=0 -p $PORT +timeout=3 $i @$DNS &
		WAIT="$WAIT $!"
		let a=a+1
	else
		dig +retry=0 -p $PORT +timeout=3 $i @$DNS
		let a=0
		wait $WAIT 
	fi
done | tee my.count | awk -v tot=$NUM -v times=0 -v noerr=0 -F ' ' 'BEGIN {tsum=0; mism=0; nxdom=0; formerr=0; servfail=0;tout=0} { if (/Query time/) {tsum+=$4 ; times+=1;}; if (/SERVFAIL/) {servfail+=1;}; if (/NOERROR/) {noerr+=1;}; if (/mismatch/) {mism+=1}; if (/NXDOMAIN/) {nxdom+=1}; if (/FORMERR,/) {formerr+=1}; if (/timed out,/) {tout+=1}; } { if (/; <<>>/) {print $0}; if (/HEADER/) {print $0}; if (/mismatch/) {print $0}; if (/connection/) {print $0} } END { print "\nAverage query time: "tsum/tot" ms ("times"/"tot") [ NOERR:"noerr" ERR_MISMATCH:"mism" ERR_FORMERR:"formerr" ERR_NXDOMAIN:"nxdom" ERR_SERVFAIL:"servfail" ERR_TIMEOUT:"tout" ]\n" }'
#|grep time
#dig {} @$DNS | grep -E '^[A-Za-z0-9]|Query time' | \
echo "Request received SERVFAIL: "$(grep -c 'SERVFAIL' my.count)/$NUM
echo "Request section mismatch : "$(grep -c 'mismatch' my.count)/$NUM
echo "Request failed timeout   : "$(grep -c 'timed out' my.count)/$NUM
echo "Connection refused       : "$(grep -c 'connection refused' my.count)/$NUM
#;; connection timed out; no servers could be reached

