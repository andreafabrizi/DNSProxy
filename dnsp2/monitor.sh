#!/bin/bash

DNS=$1
NUM=$2

if [ -z $1 ] || [ -z $2 ] ; then echo "parameters missing"; exit 127; fi

cat DNS.txt | head -$NUM | xargs -n 10 -I {} -P $(echo $NUM/10| bc) \
dig {} @$DNS | grep -E '^[A-Za-z0-9]|Query time' | \
awk -v xxx=$NUM 'begin{sum=0}{/Query time/(sum+=$4)}END{print "Average query time: "sum/xxx" ms"}'
