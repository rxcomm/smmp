#!/bin/bash
# usage: ./socat.sh <server address> <local port>
if [ $1x = "x" ] || [ $2x = "x" ]; then
  echo "Usage: ./socat.sh <server address> <local port>"
  exit 0
fi

SMMP_SERVER_PORT=50000

socat TCP4-LISTEN:$2,fork SOCKS4A:localhost:$1:$SMMP_SERVER_PORT,socksport=9050 &
