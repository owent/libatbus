#!/bin/sh
# Copyright 2026 atframework

ADDRESS="ipv6://::1:16389";
UNIT_SIZE=1024 ;
LIMIT_SIZE=4194304 ;
STATIC_LIMIT_NUM=1024 ;

if [ $# -ge 1 ]; then
    ADDRESS="$1";
fi

if [ $# -ge 2 ]; then
    UNIT_SIZE=$2 ;
fi

if [ $# -ge 3 ]; then
    LIMIT_SIZE=$3 ;
fi

if [ $# -ge 4 ]; then
    STATIC_LIMIT_NUM=$4 ;
fi

./benchmark_io_stream_channel_recv "$ADDRESS" $UNIT_SIZE > recv-ios.log 2>&1 &

sleep 2;

for ((i=1;i<=16;++i)); do
    ./benchmark_io_stream_channel_send "$ADDRESS" $UNIT_SIZE $LIMIT_SIZE $STATIC_LIMIT_NUM > send-ios-$i.log 2>&1 &
done


