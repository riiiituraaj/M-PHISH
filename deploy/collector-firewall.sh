#!/bin/sh
# Linux iptables backend. Review subnet conflicts first. No global flush.
set -eu
subnet=172.31.90.10/32
iptables -N MPHISH_EGRESS 2>/dev/null || true
iptables -F MPHISH_EGRESS
iptables -A MPHISH_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for range in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
  iptables -A MPHISH_EGRESS -d "$range" -j REJECT
done
iptables -A MPHISH_EGRESS -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A MPHISH_EGRESS -j REJECT
iptables -C DOCKER-USER -s "$subnet" -j MPHISH_EGRESS 2>/dev/null || iptables -I DOCKER-USER 1 -s "$subnet" -j MPHISH_EGRESS
iptables -C INPUT -s "$subnet" -m conntrack --ctstate NEW -j REJECT 2>/dev/null || iptables -I INPUT 1 -s "$subnet" -m conntrack --ctstate NEW -j REJECT
