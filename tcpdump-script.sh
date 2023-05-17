#!/bin/bash

tcpdump -n -i eth0 icmp | awk '{print $3}' | awk -F\. '{print $1"."$2"."$3"."$4}' | sort | uniq -c
