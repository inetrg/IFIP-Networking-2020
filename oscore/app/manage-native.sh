#!/usr/bin/env bash

# single setup to build for native over tap0/tap1 bridge

set -x

GW="1"
NARRNUM=0

NODES[1]="2001:db8::3c63:beff:fe85:ca96"
NODES[2]="2001:db8::1858:ffff:fe93:b004"

rm -f idaddr.inc

for i in ${!NODES[*]}; do
    if [ "${GW}" != "${i}" ]; then
        NARR="$i,${NARR}"
        NARRADDR="\"${NODES[$i]}\",${NARRADDR}"
        printf "MYMAP($NARRNUM,$i,\"${NODES[$i]}\")\n" >> idaddr.inc
        ((NARRNUM=NARRNUM+1))
    fi
done

NARR="-DNARR='{ ${NARR::-1} }' -DNARRNUM=${NARRNUM}"

CFLAGS="-DGW=0 ${NARR}" make -j4 all BOARD=native
cp bin/native/app.elf app_node.elf
CFLAGS="-DGW=1 ${NARR}" make -j4 all BOARD=native
cp bin/native/app.elf app_gw.elf

echo "Now run as \`./app_gw.elf tap0\` and \`./app_node.elf tap1\`"
