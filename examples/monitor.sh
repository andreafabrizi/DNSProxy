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

head -$NUM $FILE | xargs -n 5 -I {} -P $(echo $NUM/5| bc) \
dig +retry=0 -p $PORT @$DNS {} | grep -E '^[A-Za-z0-9]|Query time' | \
awk -v xxx=$NUM 'begin{sum=0}{if (/Query time/) sum+=$4} END { print "\nAverage query time: "sum/xxx" ms"}'

