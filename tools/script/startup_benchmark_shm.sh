#!/bin/sh
# Copyright 2026 atframework

ADDRESS=12345679 ;
UNIT_SIZE=1024 ;
SHM_SIZE=16777216 ; # 16MB

if [ $# -ge 1 ]; then
    ADDRESS="$1";
fi

if [ $# -ge 2 ]; then
    UNIT_SIZE=$2 ;
fi

./benchmark_shm_channel_recv $ADDRESS $UNIT_SIZE $SHM_SIZE > recv-shm.log 2>&1 &

sleep 2;

for ((i=1;i<=16;++i)); do
    ./benchmark_shm_channel_send $ADDRESS $UNIT_SIZE $SHM_SIZE > send-shm-$i.log 2>&1 &
done


