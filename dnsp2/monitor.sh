#!/bin/bash

DNS=$1
PORT=$2
NUM=$3

if [ -z $1 ] || [ -z $2 ] || [ -z $3 ] ; then echo "parameters missing"; exit 127; fi

cat DNS.txt | head -$NUM | xargs -n 100 -I {} -P $(echo $NUM/10| bc) \
dig -p $PORT {} @$DNS | grep -E '^[A-Za-z0-9]|Query time' | \
awk -v xxx=$NUM 'begin{sum=0}{/Query time/(sum+=$4)}END{print "\nAverage query time: "sum/xxx" ms"}'
