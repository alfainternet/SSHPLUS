#!/bin/bash
# Badvpn - sshplus manager
port=$1
[[ -z $port ]] && port="7300"
badvpn-udpgw --listen-addr 127.0.0.1:$port --max-clients 10000 --max-connections-for-client 1000 > /dev/null 2>&1
