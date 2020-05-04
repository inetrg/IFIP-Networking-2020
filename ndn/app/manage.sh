#!/usr/bin/env bash
set -x

GW="289"
NARRNUM=0

declare -A NODES

if [ "$1" == "single" ]; then
    NODES[1]="32:88"
    NODES[70]="02:BB"
    NODES[281]="36:5E"
    NODES[282]="32:5F"
    NODES[283]="26:5D"
    NODES[284]="0A:A9"
    NODES[285]="36:5F"
    NODES[286]="3A:B5"
    NODES[287]="2A:5E"
    NODES[288]="02:BE"
    NODES[289]="52:AC"
fi
if [ "$1" == "multi" ]; then
    NODES[274]="3A:5C"
    NODES[275]="06:AD"
    NODES[276]="06:5E"
    NODES[277]="52:AA"
    NODES[278]="3A:B4"
    NODES[279]="06:5C"
    NODES[280]="22:5D"
    NODES[281]="36:5E"
    NODES[282]="32:5F"
    NODES[283]="26:5D"
    nodes[289]="52:ac"
fi

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

CFLAGS="-DGW=0 ${NARR}" make -j4 all BOARD=iotlab-m3
cp bin/iotlab-m3/app.elf app_node.elf
CFLAGS="-DGW=1 ${NARR}" make -j4 all BOARD=iotlab-m3
cp bin/iotlab-m3/app.elf app_gw.elf

set +x
