#!/usr/bin/env bash
set -x

GW="289"
NARRNUM=0

declare -A NODES

if [ "$1" == "single" ]; then
    NODES[1]="2001:db8::3088:f465:106b:1115"
    NODES[70]="2001:db8::bb:f765:106b:1115"
    NODES[281]="2001:db8::345e:fe65:106b:1115"
    NODES[282]="2001:db8::305f:f365:106b:1115"
    NODES[283]="2001:db8::245d:fa65:106b:1115"
    NODES[284]="2001:db8::8a9:fa65:106b:1115"
    NODES[285]="2001:db8::345f:f765:106b:1115"
    NODES[286]="2001:db8::38b5:fb65:106b:1115"
    NODES[287]="2001:db8::285e:fb65:106b:1115"
    NODES[288]="2001:db8::be:fd65:106b:1115"
    NODES[289]="2001:db8::50ac:fd65:106b:1115"
fi
if [ "$1" == "multi" ]; then
    NODES[274]="2001:db8::385c:fa65:106b:1115"
    NODES[275]="2001:db8::4ad:fa65:106b:1115"
    NODES[276]="2001:db8::45e:f865:106b:1115"
    NODES[277]="2001:db8::50aa:f965:106b:1115"
    NODES[278]="2001:db8::38b4:f965:106b:1115"
    NODES[279]="2001:db8::45c:fd65:106b:1115"
    NODES[280]="2001:db8::205d:f965:106b:1115"
    NODES[281]="2001:db8::345e:fe65:106b:1115"
    NODES[282]="2001:db8::305f:f365:106b:1115"
    NODES[283]="2001:db8::245d:fa65:106b:1115"
    NODES[289]="2001:db8::50ac:fd65:106b:1115"
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
